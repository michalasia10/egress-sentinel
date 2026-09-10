# Roadmap

## 0.1 — prove the security boundary

Deliver a local Sentry Envelope gateway with one policy engine and no control
plane.

- `es-core`, `es-policy`, `es-detect`, `es-protocol`, `es-forwarder`,
  `es-audit`, `es-service`, `es-gateway`, and `es-cli` in the documented order.
- Destination allow-list, project authentication, bounded request handling, and
  YAML validation.
- Header/body redaction, simple secret detection, HMAC pseudonymization,
  drop/quarantine decisions, and SQLite audit metadata.
- CLI commands: `validate`, `test`, `explain`.
- Fixtures: JWT in a header, personal data in a request body, and a connection
  string in a stack trace.
- Docker Compose demo and a repeatable end-to-end test against a fake upstream.

## 0.2 — open telemetry and operational resilience

- OTLP/HTTP logs and traces receiver plus OTLP forwarding.
- Dry-run mode that produces decisions without forwarding.
- Encrypted bounded disk spool for retry.
- Helm chart, alert webhook, and maintained framework policy packs.

## 1.0 — managed governance, optionally

- EU-hosted or self-hosted control plane.
- Signed configuration distribution, RBAC, audit dashboard, policy history, and
  GitHub/GitLab policy checks.
- OTLP/gRPC and multi-project routing.

No dashboard work should begin until several target users have exercised the
local gateway with realistic telemetry and policy fixtures.
