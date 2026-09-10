# Policy Contract

Policies are declarative YAML files. They are validated and compiled before
activation. A policy error prevents activation rather than weakening egress
controls.

## Example

```yaml
version: 1
destinations:
  - id: sentry-eu
    protocol: sentry
    allowed_hosts: [o123.ingest.eu.sentry.io]
rules:
  - id: remove-sensitive-headers
    match:
      json_path: $.request.headers.*
      key_matches: [authorization, cookie, set-cookie, x-api-key]
    action: remove
  - id: pseudonymize-user-id
    match:
      paths: [$.user.id, $.attributes.tenant_id]
    action: hmac_sha256
    key_ref: local-correlation-key
  - id: quarantine-secrets
    detect:
      types: [jwt, api_key, private_key, connection_string]
    action: quarantine
limits:
  max_event_size: 256kb
  max_string_field_length: 4096
  events_per_minute_per_project: 1000
security:
  reject_unknown_projects: true
  reject_attachments: true
```

## Actions

| Action | Meaning |
| --- | --- |
| `remove` | Delete a matching field. |
| `replace` | Replace a value with a fixed marker. |
| `mask` | Preserve an explicitly configured portion of a value. |
| `hmac_sha256` | Produce a stable pseudonym using a local key reference. |
| `drop_event` | Reject the complete event. |
| `quarantine` | Do not forward the event; record the configured safe audit outcome. |
| `route` | Send the sanitized event to another named approved destination. |

## Evaluation rules

Rules run in their declared order. A terminal action (`drop_event` or
`quarantine`) stops evaluation. `route` can only reference a declared
destination compatible with the normalized protocol. A policy test must assert
both the final result and the applied rule IDs.

Secrets referenced through `key_ref` are supplied by the local deployment; they
are never serialized into a policy, test fixture, audit record, or `explain`
output.
