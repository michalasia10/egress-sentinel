# Egress Sentinel

Egress Sentinel is a self-hosted security gateway for observability data. It
inspects Sentry Envelopes and OpenTelemetry payloads before they leave a
customer-controlled network, applies versioned policy, records safe audit
metadata, and forwards only approved sanitized data.

> Control, clean, and audit telemetry before it leaves your infrastructure.

It is not a log store, SIEM, DLP suite, or a legal-compliance guarantee. Its
scope is deterministic enforcement of data-egress policy for telemetry.

## MVP

- Sentry Envelope reverse proxy with an explicit destination allow-list.
- YAML policy with field removal, replacement, masking, HMAC pseudonymization,
  dropping, quarantine, and routing.
- Bounded parsing, request limits, project authentication, and basic secret
  detectors.
- SQLite audit metadata that never retains raw payloads by default.
- `egress-sentinel validate`, `test`, and `explain` CLI commands.
- Docker Compose deployment; no hosted dashboard or control plane.

## Architecture

The local data plane is the product. It receives telemetry, normalizes it,
validates limits and schemas, evaluates policy, writes an audit decision, and
forwards only an approved sanitized representation.

```text
SDKs -> es-gateway -> es-protocol -> es-service -> es-policy / es-detect
                                                 -> es-audit
                                                 -> es-forwarder -> approved backend
```

Read [the architecture](docs/architecture.md), [the policy contract](docs/policy-contract.md),
and [the MVP plan](docs/roadmap.md) before adding implementation code.

## Documentation

- [Product vision](docs/product-vision.md)
- [Threat model](docs/threat-model.md)
- [Audit model](docs/audit-model.md)
- [Crate boundaries](docs/crates/README.md)
- [Engineering guide](docs/cargo-guide.md)

## Status

Documentation scaffold only. The workspace and crates should be added in the
order defined in [the roadmap](docs/roadmap.md).
