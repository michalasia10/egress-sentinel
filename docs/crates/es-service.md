# es-service

**Role:** the only use-case layer that composes the gateway decision pipeline.

It authenticates project context supplied by the adapter, coordinates normalized
input, limits, detection, policy evaluation, transformation, audit persistence,
and forwarding. It exposes stable operations for both `es-gateway` and `es-cli`.

It does not implement HTTP routing, command parsing, raw protocol parsing, or
SQLite queries itself. It depends on the lower-level workspace crates.
