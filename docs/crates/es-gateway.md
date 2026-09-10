# es-gateway

**Role:** inbound HTTP adapter and the runtime binary for the local data plane.

It owns Axum routes, authentication extraction, streaming/body limits,
request-to-service mapping, safe HTTP errors, readiness, and metrics plumbing.
It calls `es-service` and contains no redaction rules, destination selection, or
audit SQL.

It depends on `es-service` and HTTP runtime libraries.
