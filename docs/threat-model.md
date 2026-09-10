# Threat Model

## Assets to protect

- Raw telemetry, including headers, bodies, stack traces, attributes, and
  attachments.
- Credentials and correlation keys used by the gateway.
- Policy integrity, destination configuration, and audit integrity.
- Availability of the telemetry pipeline without bypassing policy.

## Trust boundaries

1. Client SDKs are untrusted producers: they can send malformed, oversized, or
   deliberately secret-bearing telemetry.
2. The gateway data plane is trusted to enforce the locally activated policy.
3. Observability vendors and future control planes are external recipients and
   receive only approved sanitized output or safe aggregate metadata.
4. Local policy, key material, and the audit database are operator-controlled
   assets and require filesystem, secret-store, and access controls.

## Primary threats and controls

| Threat | Required control |
| --- | --- |
| Secret or PII exfiltration | Allow-list schemas, field rules, detectors, and terminal actions before forwarding. |
| SSRF or destination bypass | Named destinations, host allow-lists, protocol compatibility checks, and no client-controlled outbound URL. |
| Resource exhaustion | Request, field, attachment, and rate limits; bounded parsing; backpressure. |
| Policy tampering | Git-reviewed configuration, validation, version/digest audit fields, least-privileged filesystem access. |
| Raw data leakage through observability | Structured redacted gateway logs and audit records that contain no raw field values. |
| Key disclosure | `key_ref` indirection, local secret injection, and no secret serialization or error rendering. |
| Upstream failure | Explicit fail-open/fail-closed policy per destination; later encrypted disk spool, never an unbounded in-memory queue. |

## Residual risk

Pattern and entropy detectors cannot find every sensitive value. The strongest
control is an allow-list schema that removes unknown fields. Operators remain
responsible for policy review, secret management, network controls, and legal
compliance decisions.
