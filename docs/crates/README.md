# Crate Boundaries

Each crate owns one responsibility. Dependencies point inward toward `es-core`.

| Crate | Role |
| --- | --- |
| [es-core](es-core.md) | Domain vocabulary and safe shared types. |
| [es-policy](es-policy.md) | Policy parsing, compilation, and evaluation. |
| [es-detect](es-detect.md) | Deterministic secret and PII detectors. |
| [es-protocol](es-protocol.md) | Sentry and OTLP parsing and normalization. |
| [es-forwarder](es-forwarder.md) | Approved outbound transport. |
| [es-audit](es-audit.md) | Safe local audit persistence. |
| [es-service](es-service.md) | The decision pipeline and use cases. |
| [es-gateway](es-gateway.md) | Inbound HTTP adapter. |
| [es-cli](es-cli.md) | Human and CI-facing command-line adapter. |
