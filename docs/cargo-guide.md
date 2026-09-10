# Engineering Guide

Create a virtual Cargo workspace with `members = ["crates/*"]`. Add crates in
the roadmap order so the compiler enforces the intended boundaries.

## Conventions

- Crate names use the `es-` prefix; directories match crate names.
- Libraries use `thiserror`; the `es-cli` binary may use `anyhow` at its edge.
- `lib.rs` is a small public table of contents. Put behavior in focused modules.
- Unit tests live with the code; integration tests exercise only public APIs.
- Commit `Cargo.lock` because the workspace ships binaries.
- Use workspace dependencies and workspace lints in every member crate.

## Quality gates

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

For this security-sensitive service, tests must include malformed input, limit
violations, policy compilation failures, destination bypass attempts, and proof
that raw values do not appear in audit or application logs.

## Suggested initial dependencies

Use `tokio`, `axum`, `hyper` or the Axum stack, `serde`, `serde_yaml`,
`serde_json`, `thiserror`, `hmac`, `sha2`, `regex`, `rusqlite`, and `clap` only
after confirming the exact crate capabilities and license policy. Keep protocol
and parser dependencies behind their owning crates.
