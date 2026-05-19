# Changelog

## [1.0.3] - 2026-05-18

### Security
- Changed SSL hostname verification default from disabled to enabled in
  `integration_client.py`, `globalConfig.json`, and `kafka_publish_cmd.py`
- Added `_redact_sensitive()` helper in `ansible_itsi.py` to mask
  `session_key`, `basic_password`, `token`, and `sasl_plain_password`
  before debug logging
