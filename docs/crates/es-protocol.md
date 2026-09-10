# es-protocol

**Role:** parse, validate, normalize, and serialize telemetry protocols.

The MVP owns Sentry Envelope handling. OTLP/HTTP joins later behind the same
normalized event model. Parsing must be size-bounded and must produce safe error
types that never embed raw payload snippets.

It does not run policy, select an outbound endpoint, persist data, or expose HTTP
routes. It depends on `es-core`.
