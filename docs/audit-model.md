# Audit Model

Audit data is evidence of a gateway decision, not a copy of telemetry.

## Required decision fields

```text
timestamp
project_id
source_protocol
destination_id
outcome                 # forwarded, dropped, quarantined, rejected, failed
policy_version
policy_digest
applied_rule_ids
detection_categories    # e.g. jwt, api_key; never matched values
payload_size_bytes
raw_payload_stored      # always false in the MVP
```

The MVP stores rows locally in SQLite. It does not persist raw request bodies,
headers, stack traces, attachment contents, full URLs, or HMAC outputs unless an
operator has made a separate, explicit retention decision outside the default
model.

## Integrity and privacy

- Audit writes must use parameterized SQL and bounded field lengths.
- The service logs audit-write failure without reproducing the event payload.
- An audit-store outage has an explicit deployment policy. The secure default is
  to reject forwarding when required audit evidence cannot be recorded.
- Aggregated metrics may count rule hits and outcomes, but must not use sensitive
  field values as labels.
