# Repository guidance

Follow the repository's Rust readability and domain-style guidance in
[`docs/architecture/rust-style.md`](docs/architecture/rust-style.md).

For readability-focused changes, use the incremental refactoring process in
[`docs/refactoring/readability.md`](docs/refactoring/readability.md).

Rust formatting and repository checks are configured in:

- [`rustfmt.toml`](rustfmt.toml)
- [`rust-toolchain.toml`](rust-toolchain.toml)
- [`.pre-commit-config.yaml`](.pre-commit-config.yaml)

## Implementation preferences

- Prefer domain objects and methods that own their state and invariants.
- Avoid large methods that orchestrate a flow, validate several independent
  structures, and assemble the result at the same time.
- Limit private helpers; do not extract a function merely to shorten a method.
  Every new object or method should have a clear domain responsibility.
- During refactoring, also improve existing code in the directly affected area
  when it improves readability without changing the contract.
- Keep the main operation flow short and readable, and place validation details
  on the types they concern.

## Commit conventions

- Commit small, meaningful changes that each represent one coherent semantic
  change.
- Use Conventional Commit prefixes: `fix` for bug fixes, `feat` for new
  behavior, and `chore` for maintenance or non-behavioral changes.
- Keep commit subjects concise and describe the user-visible or repository
  semantic change, for example `fix(policy): reject invalid host labels`.
- Follow the [Conventional Commits specification](https://www.conventionalcommits.org/en/v1.0.0-beta.2/).
