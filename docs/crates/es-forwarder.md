# es-forwarder

**Role:** perform outbound delivery only to a validated named destination.

It owns TLS-aware HTTP transport, protocol-specific request construction,
timeouts, response classification, and later retry/spool integration. It accepts
sanitized data and a destination selected by `es-service`; it cannot accept a
free-form client URL.

It depends on `es-core` and transport libraries, not on gateway routes or policy
parsing.
