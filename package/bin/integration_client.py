#!/usr/bin/env python3
# coding=utf-8
"""
integration_client.py

Shared helper library to send data to a webhook using chunking, concurrency,
SSL checks, optional authentication, and an optional "raw payload" mode.

Logic:
-------------
1) get_webhook_env_config():
   - Reads the add-on conf 'ansible_addon_for_splunk_environment.conf' for a stanza
     matching `integration_type=webhook` and `environment=<env>`.

2) send_data_webhook_async():
   - Accepts any 'all_results' data (a single base64-gzipped string or a list of records).
   - Splits large lists into chunks (batches) for concurrency.
   - Toggles between:
       (A) "wrapped" mode => adds a top-level JSON structure { sid, search_name, ..., results: chunk }
       (B) "raw" mode => sends 'chunk' as the entire top-level JSON (bypassing the universal wrapper).

Usage:
-------
1) In your Splunk Core custom alert:
   - Keep raw_payload_mode=False to produce the old structure with "sid" and "results".
2) In your ITSI script:
   - Build a fully custom JSON for each episode, pass raw_payload_mode=True, so
     the code won't wrap your dictionary.

Retains all concurrency, chunking, SSL, auth, and retry logic from your
existing solution.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import asyncio
import httpcore
import logging
from typing import Any, Optional, List, Dict

import httpx
import httpx_auth
from solnlib import conf_manager
from solnlib.log import Logs

Logs.set_context(
    directory=f"{os.environ.get('SPLUNK_HOME', '/opt/splunk')}/var/log/splunk",
    namespace="ansible_addon_for_splunk"
)
logger = Logs().get_logger("integration_client")
httpx_logger = logging.getLogger("httpx")
httpcore_logger = logging.getLogger("httpcore")
httpx_logger.handlers = logger.handlers
httpcore_logger.handlers = logger.handlers

def update_dynamic_log_level(logger, session_key, app_name):
    """
    Reads the [logging] stanza from ansible_addon_for_splunk_settings.conf and
    sets the log level for the given logger.
    
    :param logger: a logger object (from solnlib.log.Logs.get_logger)
    :param session_key: Splunk session key (string)
    :param app_name: The app name (e.g. "ansible_addon_for_splunk")
    """
    try:
        if not session_key:
            logger.warning("No session key available; defaulting log level to INFO.")
            logger.setLevel(logging.INFO)
            return
        cfm = conf_manager.ConfManager(
            session_key,
            app_name,
            realm=f"__REST_CREDENTIAL__#{app_name}#configs/conf-ansible_addon_for_splunk_settings"
        )
        settings_conf = cfm.get_conf("ansible_addon_for_splunk_settings").get("logging")
        loglevel_str = settings_conf.get("loglevel", "INFO").upper().strip()
        level = getattr(logging, loglevel_str, logging.INFO)
        logger.setLevel(level)
        logger.info(f"Dynamic log level set to {loglevel_str} ({level}).")
    except Exception as e:
        logger.warning("Unable to set dynamic log level: %s", e)
        logger.setLevel(logging.INFO)

MAX_RECORDS_PER_BATCH = 100
MAX_CONCURRENCY = 1

###############################################################################
# SSL CERT FILE
###############################################################################
def set_ssl_cert_file():
    """
    Set SSL_CERT_FILE environment variable to the correct CA certificates file path,
    detected among common Linux / BSD / macOS distros.
    """
    common_cert_paths = [
        "/etc/ssl/certs/ca-certificates.crt",             # Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",               # Red Hat/CentOS/Fedora
        "/etc/ssl/ca-bundle.pem",                         # OpenSUSE/SLES
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL 8 / CentOS 8
        "/usr/local/share/certs/ca-root-nss.crt",         # FreeBSD
        "/etc/ssl/cert.pem"                               # macOS
    ]
    for cert_path in common_cert_paths:
        if os.path.isfile(cert_path):
            os.environ["SSL_CERT_FILE"] = cert_path
            logger.debug(f"SSL_CERT_FILE set to: {cert_path}")
            return

    raise FileNotFoundError("No valid CA certificates file found. Configure SSL_CERT_FILE manually.")

set_ssl_cert_file()

###############################################################################
# 1) get_webhook_env_config
###############################################################################
def get_webhook_env_config(environment: str, session_key: str, app_context: str = "ansible_addon_for_splunk") -> dict:
    """
    Reads the stanza matching:
      integration_type=webhook
      environment=<env>
    from ansible_addon_for_splunk_environment.conf
    """
    if not session_key:
        raise ValueError("Missing session_key for configuration retrieval.")

    realm = f"__REST_CREDENTIAL__#{app_context}#configs/conf-ansible_addon_for_splunk_environment"
    logger.debug(f"[get_webhook_env_config] environment={environment}, realm={realm}")

    try:
        cfm = conf_manager.ConfManager(session_key, app_context, realm=realm)
        env_conf = cfm.get_conf("ansible_addon_for_splunk_environment").get_all()
        logger.debug(f"Retrieved {len(env_conf)} stanzas from ansible_addon_for_splunk_environment.conf")
    except Exception as e:
        logger.error(f"Error retrieving environment config: {e}")
        raise

    for stanza_name, stanza_data in env_conf.items():
        if stanza_data.get("integration_type") == "webhook" and stanza_data.get("environment") == environment:
            logger.debug(f"Matched environment '{environment}' in stanza '{stanza_name}'")
            return stanza_data

    err_msg = f"No webhook stanza found for environment='{environment}' in ansible_addon_for_splunk_environment.conf"
    logger.error(err_msg)
    raise ValueError(err_msg)

###############################################################################
# 2) send_data_webhook_async (with raw_payload_mode toggle)
###############################################################################
async def send_data_webhook_async(
    all_results: Any,
    sid: Optional[str],
    search_name: Optional[str],
    owner: Optional[str],
    app: Optional[str],
    results_web_link: Optional[str],
    results_rest_link: Optional[str],
    env_config: dict,
    send_all_results_mode: str,
    results_per_batch: int,
    raw_payload_mode: bool = False
) -> None:
    """
    Asynchronously sends 'all_results' to the configured webhook.

    :param all_results: Data to send (str or list).
    :param sid: Search ID (optional).
    :param search_name: Name of the search/alert (optional).
    :param owner: Owner of the alert (optional).
    :param app: App context (optional).
    :param results_web_link: Splunk UI link to results (optional).
    :param results_rest_link: Splunk REST link to results (optional).
    :param env_config: Configuration dict from get_webhook_env_config().
    :param send_all_results_mode: "plaintext", "compressed", or "no" (to pick your logic).
    :param results_per_batch: chunk size for large lists.
    :param raw_payload_mode: If True, we skip the universal wrapper and send each
                             'chunk' exactly as-is as the top-level JSON.
                             If False, we wrap chunk in {"sid":..., "results": chunk}.
    """
    logger.debug(f"send_data_webhook_async called => raw_payload_mode={raw_payload_mode}, mode={send_all_results_mode}")

    url = env_config.get("webhook_endpoint")
    if not url:
        raise ValueError("No 'webhook_endpoint' in environment config")
    # SSL verification
    ssl_check = env_config.get("ssl_check_hostname", "true").lower()
    verify_ssl = ssl_check in ["1", "true", "yes"]
    # Timeouts / Retry
    connect_timeout = float(env_config.get("connection_timeout", "10"))
    max_retries = int(env_config.get("retries", "3"))
    transport = httpx.AsyncHTTPTransport(retries=max_retries, verify=verify_ssl)
    timeouts = httpx.Timeout(connect=connect_timeout, read=30.0, write=30.0, pool=30.0)
    # Authentication
    auth_type = env_config.get("auth_type", "none").lower()
    basic_username = env_config.get("basic_username", "")
    basic_password = env_config.get("basic_password", "")
    token = env_config.get("token", "")
    auth = None
    if auth_type == "basic" and basic_username and basic_password:
        logger.debug("Using Basic Auth for webhook.")
        auth = httpx_auth.Basic(basic_username, basic_password)
    elif auth_type in ("apikey", "api_key") and token:
        logger.debug("Using Bearer token in Authorization header for webhook.")
        auth = httpx_auth.HeaderApiKey(api_key=f"Bearer {token}", header_name="Authorization")
    else:
        logger.debug("No or unsupported authentication. Proceeding without auth.")

    async def trace_callback(event_name, info):
        logger.debug(f"TRACE EVENT: {event_name} => {info}")
    # We'll create a single httpx client for all requests
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    async with httpx.AsyncClient(
        verify=verify_ssl,
        auth=auth,
        transport=transport,
        timeout=timeouts
    ) as client:
        if isinstance(all_results, str):
            # Compressed => one chunk
            logger.debug("Detected compressed base64 => single-chunk POST.")
            await _send_single_chunk(
                client=client,
                url=url,
                sid=sid,
                search_name=search_name,
                owner=owner,
                app=app,
                results_web_link=results_web_link,
                results_rest_link=results_rest_link,
                chunk=all_results,
                trace_func=trace_callback,
                raw_payload_mode=raw_payload_mode
            )
        elif isinstance(all_results, list) and len(all_results) == 1:
            # Single record => single-chunk
            logger.debug("Detected single record => single-chunk POST.")
            await _send_single_chunk(
                client=client,
                url=url,
                sid=sid,
                search_name=search_name,
                owner=owner,
                app=app,
                results_web_link=results_web_link,
                results_rest_link=results_rest_link,
                chunk=all_results[0],
                trace_func=trace_callback,
                raw_payload_mode=raw_payload_mode
            )
        elif isinstance(all_results, list):
            if raw_payload_mode:
                ##############################################################
                # ITSI MODE: Send each record individually regardless of batch size
                ##############################################################
                logger.debug(f"Raw payload mode: Sending {len(all_results)} ITSI episodes individually")
                tasks = [
                    _send_chunk_with_sem(
                        sem,
                        client,
                        url,
                        None,  # ITSI-specific: metadata not used
                        None,
                        None,
                        None,
                        None,
                        None,
                        single_record,
                        trace_callback,
                        True
                    )
                    for single_record in all_results
                ]
                await asyncio.gather(*tasks)
            else:
                # Standard batching for Splunk Core alerts
                logger.debug(f"Detected multiple records => chunking into {results_per_batch} per batch (total={len(all_results)})")
                tasks = []
                for sub_chunk in _chunk_results(all_results, results_per_batch):
                    tasks.append(
                        _send_chunk_with_sem(
                            sem,
                            client,
                            url,
                            sid,
                            search_name,
                            owner,
                            app,
                            results_web_link,
                            results_rest_link,
                            sub_chunk,
                            trace_callback,
                            raw_payload_mode
                        )
                    )
            await asyncio.gather(*tasks)
        else:
            msg = f"all_results must be a string or list, found type={type(all_results)}"
            logger.error(msg)
            raise ValueError(msg)

    logger.info(f"Completed sending data to webhook => {url}")

###############################################################################
# 3) Internal chunking + concurrency
###############################################################################
def _chunk_results(all_results: List[Any], chunk_size: int):
    total = len(all_results)
    logger.debug(f"[_chunk_results] chunking total={total}, chunk_size={chunk_size}")
    for i in range(0, total, chunk_size):
        yield all_results[i : i + chunk_size]

async def _send_chunk_with_sem(
    sem: asyncio.Semaphore,
    client: httpx.AsyncClient,
    url: str,
    sid: Optional[str],
    search_name: Optional[str],
    owner: Optional[str],
    app: Optional[str],
    results_web_link: Optional[str],
    results_rest_link: Optional[str],
    chunk: Any,
    trace_func,
    raw_payload_mode: bool
):
    async with sem:
        await _send_single_chunk(
            client, url, sid, search_name, owner, app,
            results_web_link, results_rest_link, chunk,
            trace_func, raw_payload_mode
        )

async def _send_single_chunk(
    client: httpx.AsyncClient,
    url: str,
    sid: Optional[str],
    search_name: Optional[str],
    owner: Optional[str],
    app: Optional[str],
    results_web_link: Optional[str],
    results_rest_link: Optional[str],
    chunk: Any,
    trace_func,
    raw_payload_mode: bool
) -> None:
    """
    Sends one "chunk" of data. If raw_payload_mode=True, we send 'chunk' directly.
    If raw_payload_mode=False, we do the old "wrapper" approach.

    For "compressed" data, chunk is a base64-encoded string.
    For "plaintext" data, chunk is typically a list or dict.
    """
    # Decide how to build the JSON payload
    if raw_payload_mode:
        # We skip the universal wrapper. 'chunk' must be the entire top-level JSON.
        payload = chunk  # must be a dict if plaintext, or a single string if you want direct posting
        logger.debug("[_send_single_chunk] raw_payload_mode=True => sending 'chunk' as top-level payload.")
    else:
        # Use the old universal wrapper approach
        if isinstance(chunk, str):
            # Compressed
            payload = {
                "sid": sid,
                "search_name": search_name,
                "owner": owner,
                "app": app,
                "results_web_link": results_web_link,
                "results_rest_link": results_rest_link,
                "results": {"base64_gzip": chunk},
            }
            logger.debug("[_send_single_chunk] universal wrapper w/ base64_gzip")
        else:
            # Plaintext
            payload = {
                "sid": sid,
                "search_name": search_name,
                "owner": owner,
                "app": app,
                "results_web_link": results_web_link,
                "results_rest_link": results_rest_link,
                "results": chunk
            }
            logger.debug("[_send_single_chunk] universal wrapper w/ 'results'")

    # Logging (size)
    if isinstance(payload, dict):
        size_str = f"(dict_keys={len(payload.keys())})"
    elif isinstance(payload, list):
        size_str = f"(list_len={len(payload)})"
    else:
        size_str = f"(type={type(payload)})"

    logger.debug(f"[_send_single_chunk] POST to {url}, {size_str}")

    # Make the HTTP request
    try:
        async with client.stream(
            "POST", url, json=payload, extensions={"trace": trace_func}
        ) as resp:
            network_stream = resp.extensions.get("network_stream")
            if network_stream is not None:
                ssl_obj = network_stream.get_extra_info("ssl_object")
                if ssl_obj:
                    ssl_ver = ssl_obj.version()
                    ssl_cipher = ssl_obj.cipher()
                    logger.debug(f"SSL version={ssl_ver}, cipher={ssl_cipher}")
                    shared_ciphers = ssl_obj.shared_ciphers()
                    logger.debug(f"SSL shared ciphers={shared_ciphers}")
                    alpn = ssl_obj.selected_alpn_protocol()
                    npn = getattr(ssl_obj, 'selected_npn_protocol', lambda: None)()
                    logger.debug(f"ALPN={alpn}, NPN={npn}")
                    ssl_compression = ssl_obj.compression()
                    logger.debug(f"SSL compression={ssl_compression}")
                    client_addr = network_stream.get_extra_info("client_addr")
                    server_addr = network_stream.get_extra_info("server_addr")
                    logger.debug(f"client_addr={client_addr}, server_addr={server_addr}")
            body_bytes = await resp.aread()
            if resp.status_code >= 400:
                logger.error(
                    f"[POST Error] {resp.status_code} to {url}, response={body_bytes[:200]!r}"
                )
                raise httpx.HTTPStatusError(
                    f"Request failed with status={resp.status_code}",
                    request=resp.request,
                    response=resp
                )

            logger.info(f"[POST Success] {resp.status_code} => {url}")
            try:
                text_body = body_bytes.decode(errors="replace")
                logger.debug(f"Response body => {text_body[:500]}")
            except UnicodeDecodeError:
                logger.debug(f"Response is binary, len={len(body_bytes)}")

    except httpx.RequestError as exc:
        logger.error(f"Network error => {exc.request.url}: {exc}")
        raise
    except httpx.HTTPStatusError:
        raise
