# Architecture

Egress Sentinel is a Cargo workspace. Crate boundaries enforce ownership and
keep protocol, policy, transport, and presentation concerns separate.

## Data-plane flow

```text
client SDK
  -> authenticate and select project
  -> parse with bounded memory and normalize
  -> validate protocol, schema, and limits
  -> detect sensitive values and evaluate policy
  -> transform, drop, quarantine, or route
  -> write audit metadata
  -> forward sanitized output to an approved destination
```

The original bytes may exist only for the duration needed to parse and transform
one request. They must not be copied into logs, errors, metrics, traces, or the
audit store.

## Workspace layout

```text
egress-sentinel/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── rustfmt.toml
├── clippy.toml
├── deny.toml
├── README.md
├── docs/
│   ├── architecture.md
│   ├── product-vision.md
│   ├── policy-contract.md
│   ├── threat-model.md
│   ├── audit-model.md
│   ├── roadmap.md
│   ├── cargo-guide.md
│   ├── adr/
│   └── crates/
├── crates/
│   ├── es-core/
│   ├── es-policy/
│   ├── es-detect/
│   ├── es-protocol/
│   ├── es-forwarder/
│   ├── es-audit/
│   ├── es-service/
│   ├── es-gateway/
│   └── es-cli/
└── deploy/
    ├── compose/
    └── helm/
```

## Dependency rule

Dependencies point inward toward `es-core`. `es-service` is the only use-case
layer that composes policy, detection, auditing, protocol handling, and
forwarding. `es-gateway` and `es-cli` are adapters and contain no business
policy.

```text
es-cli        es-gateway
   \             /
    \           /
       es-service
  /    |    |     |    \\
policy detect audit protocol forwarder
  \      |      |      |      /
               es-core
```

`es-forwarder` owns outbound HTTP/TLS behavior and destination enforcement.
The gateway must never make an ad-hoc outbound request.

## Security invariants

- The outbound target comes from a validated policy destination, never a payload
  field or client-provided URL.
- A policy has a version and a content digest; every decision records both.
- The audit write occurs before a successful response is returned to the client.
- Raw payloads, secrets, and HMAC keys never appear in diagnostics or audit rows.
- Quarantine means no external forwarding. Its local retention behavior is an
  explicit deployment decision, disabled by default in the MVP.
