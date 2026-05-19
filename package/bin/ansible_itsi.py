#!/usr/bin/env python3
# coding=utf-8

"""
ansible_itsi.py

ITSI Notable Event custom action that sends each episode
to a webhook in the same style as the default ITSI webhook code.

Logic:
-------------
1) Inherits from CustomGroupActionBase (ITSI Notable Event Actions SDK).
2) Calls self.get_group() to retrieve one or more episodes.
3) Builds the final flattened JSON for each episode, preserving fields
   like 'index', '_time', '_raw', 'itsi_group_id', etc.
4) Passes these dictionaries into integration_client.send_data_webhook_async()
   with raw_payload_mode=True => no "universal wrapper" is added.

This preserves the concurrency/retry/SSL logic in integration_client.py
while letting you replicate the default ITSI webhook's "one record => one POST"
style or chunk-based approach.

Configuration:
--------------
- Expects param.environment to pick a stanza from your
  ansible_addon_for_splunk_environment.conf for the webhook endpoint, SSL, etc.
- If you want 1 record => 1 POST, set param.results_per_batch=1.

Example usage in an Aggregation Policy:
--------------------------------------
1) In ITSI, edit or create an Aggregation Policy.
2) Under "Adaptive Response Actions," choose "ITSI Ansible Alert" (this script).
3) Provide:
   - environment (e.g. "dev"),
   - alert_type=webhook,
   - results_per_batch=1 (optional),
   - and so on.

The script is invoked with `--execute` and reads JSON from stdin.
"""

import sys
import os
import json
import asyncio

#from splunk.clilib.bundle_paths import make_splunkhome_path
#sys.path.append(make_splunkhome_path(["etc", "apps", "ansible_addon_for_splunk", "lib"]))
#sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
#sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib', 'SA_ITOA_app_common']))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.insert(0, os.path.join(os.environ.get("SPLUNK_HOME", "/opt/splunk"), "etc", "apps", "SA-ITOA", "lib"))  # ITSI SDK
sys.path.insert(0, os.path.join(os.environ.get("SPLUNK_HOME", "/opt/splunk"), "etc", "apps", "SA-ITOA", "lib", "SA_ITOA_app_common"))

from solnlib.log import Logs

from itsi.event_management.sdk.custom_group_action_base import CustomGroupActionBase
from itsi.event_management.sdk.grouping import EventGroup, GroupMeta
# from itsi.event_management.sdk.eventing import Event

import integration_client
from integration_client import update_dynamic_log_level

# from ITOA.setup_logging import getLogger
Logs.set_context(
    directory=f"{os.environ.get('SPLUNK_HOME', '/opt/splunk')}/var/log/splunk",
    namespace="ansible_addon_for_splunk"
)
# Use a clear logger name for the ITSI alert script
logger = Logs().get_logger("itsi_alert")

from ITOA.event_management.notable_event_utils import Audit
#logger = getLogger(logger_name='itsi_ansible_alert')


_SENSITIVE_KEYS = {"session_key", "basic_password", "token", "sasl_plain_password"}


def _redact_sensitive(data):
    """Return a copy of *data* with sensitive values masked for safe logging."""
    if isinstance(data, dict):
        return {
            k: ("****" if k in _SENSITIVE_KEYS and v else _redact_sensitive(v))
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [_redact_sensitive(item) for item in data]
    return data


class ITSIAnsibleAlert(CustomGroupActionBase):
    """
    Inherit from CustomGroupActionBase so we can:
      - parse JSON settings from stdin
      - access self.get_group() to iterate episodes
      - read environment config from param.environment
      - send each flattened record to the webhook in default-ITSI style
    """
    def __init__(self, settings):
        try:
            super(ITSIAnsibleAlert, self).__init__(settings, logger)
            session_key = self.get_session_key()
            update_dynamic_log_level(logger, session_key, "ansible_addon_for_splunk")
            logger.debug("Initialized ITSIAnsibleAlert with settings: %s",
                         json.dumps(_redact_sensitive(self.settings)))
        except Exception as e:
            logger.exception("Error during initialization: %s", e)
            raise

    def execute(self):
        """
        Main entry point called by ITSI Notable Event Actions.
        """
        try:
            # 1) Grab user-specified config from alert_actions.conf.
            logger.info("Starting ITSIAnsibleAlert execution.")
            config = self.get_config()
            logger.debug("[ITSIAnsibleAlert] Alert config: %s", json.dumps(_redact_sensitive(config)))

            # For example, param.environment => "dev"
            # param.alert_type => "webhook"
            # param.results_per_batch => "1"
            environment = config.get("environment", "dev")
            alert_type = config.get("alert_type", "webhook")
            results_per_batch = 1

            logger.info(f"[ITSIAnsibleAlert] environment={environment}, alert_type={alert_type}, "
                        f"results_per_batch={results_per_batch}")

            # If not webhook, we skip
            if alert_type.lower() != "webhook":
                logger.warning(f"Currently only supporting 'webhook', not '{alert_type}'")
                return

            # 2) Retrieve the session key so we can load environment config from your add-on
            session_key = self.get_session_key()
            if not session_key:
                raise ValueError("No session key found. Cannot read environment config.")

            # 3) Load environment config from ansible_addon_for_splunk_environment.conf
            env_conf = integration_client.get_webhook_env_config(
                environment=environment,
                session_key=session_key,
                app_context="ansible_addon_for_splunk"
            )
            logger.debug("[ITSIAnsibleAlert] Add-on config: %s", json.dumps(_redact_sensitive(env_conf)))

            # 4) Gather episodes via self.get_group() => yields a dictionary for each row
            episodes = []
            for data in self.get_group():
                if isinstance(data, Exception):
                    logger.error(f"Exception encountered while retrieving group data: {data}")
                    raise data
                
                # Remove empty __mv_* fields
                mv_keys_to_remove = []
                for k, v in data.items():
                    if k.startswith("__mv_") and v == "":
                        mv_keys_to_remove.append(k)
                for k in mv_keys_to_remove:
                    del data[k]

                # Set defaults if missing
                data.setdefault("index", "itsi_grouped_alerts")
                data.setdefault("sourcetype", "itsi_notable:group")
                if "_raw" not in data:
                    try:
                        data["_raw"] = json.dumps(data)
                    except Exception as e:
                        logger.exception("Error creating _raw field for episode: %s", e)
                        data["_raw"] = ""

                episodes.append(data)
            logger.info("[ITSIAnsibleAlert] Collected %s episodes from get_group().", len(episodes))

            session_key = self.get_session_key()
            eg = EventGroup(session_key=session_key)
            gm = GroupMeta(session_key=session_key)
            valid_owners = gm.get_all_owners()       # List of valid owners
            valid_severities = gm.get_all_severities()
            valid_statuses = gm.get_all_statuses()

            # Enrich each episode with tags, comments, and lists of valid attributes
            for episode in episodes:
                group_id = episode.get("itsi_group_id")  # or your field name
                if group_id:
                    try:
                        # Get all tags, comments for this specific episode
                        tags = eg.get_all_tags(group_id)
                        comments = eg.get_all_comments(group_id)
                        # Insert them into the episode dictionary
                        episode["tags"] = tags
                        episode["comments"] = comments
                    except Exception as e:
                        logger.error(f"Error retrieving tags/comments for group_id={group_id}: {e}")

            episode["valid_owners"] = valid_owners
            episode["valid_severities"] = valid_severities
            episode["valid_statuses"] = valid_statuses

            logger.debug("[ITSIAnsibleAlert] Final episode data to be sent: %s", json.dumps(episodes))
            
            logger.info("[ITSIAnsibleAlert] Starting asynchronous send of episodes to the webhook.")
            asyncio.run(
                integration_client.send_data_webhook_async(
                    all_results=episodes,              # pass each dictionary as a "record"
                    sid=None,                          # Not used in ITSI context
                    search_name=None,        # optional
                    owner=None,                        # optional
                    app=None,                        # or your app name
                    results_web_link=None,             # optional
                    results_rest_link=None,            # optional
                    env_config=env_conf,
                    send_all_results_mode="plaintext", # so integration_client treats 'episodes' as a list
                    results_per_batch=1,
                    raw_payload_mode=True              # <--- key point: skip universal wrapper
                )
            )

            logger.info("[ITSIAnsibleAlert] Successfully sent episodes to the webhook.")

        except Exception as e:
            logger.error(f"[ITSIAnsibleAlert] Execution failed. {e}")
            logger.exception(e)
            sys.exit(1)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--execute':
        try:
            input_settings = sys.stdin.read()
            try:
                logger.debug("Input settings: %s", json.dumps(_redact_sensitive(json.loads(input_settings))))
            except (json.JSONDecodeError, TypeError):
                logger.debug("Input settings: <non-JSON, redacted>")
            action = ITSIAnsibleAlert(input_settings)
            action.execute()
        except Exception as e:
            logger.error("Fatal error during ITSIAnsibleAlert execution: %s", e)
            logger.exception(e)
            sys.exit(1)

if __name__ == "__main__":
    main()
