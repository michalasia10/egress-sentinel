# Incremental readability refactoring

Status: plan only; no application refactor has been performed by adding this
document. The [Rust style guide](../architecture/rust-style.md) is the
authoritative code-design standard for every slice in this plan. This document
defines how to inspect and execute those slices; it is not a new product
milestone or an audit of current implementation.

The [workspace roadmap](workspace-roadmap.md) tracks review and refactoring
across all 14 crates, with execution order and per-crate acceptance criteria.
For a copy-ready objective and completion criteria for one named crate, use the
[one-crate refactor goal](crate-goal.md).

## Scope and constraints

Improve how Rust communicates domain behavior through cohesive structs, enums,
meaningful methods, and clearly named use cases. Prefer behavior on the object
that owns its state; do not extract private helpers just to make methods
shorter. Preserve the approved crate dependency matrix, existing ports, SQLx +
SQLite + Tokio, TEA-based TUI, public behavior, and persistent/wire
compatibility.

Do not combine readability work with a new ORM, new framework, schema redesign,
provider changes, or repository-wide renaming. A change to product behavior
needs its own explicit scope and acceptance criteria.

## Choose and inspect one operation

1. Start with an operation already being changed, or one whose mixed
   responsibilities make a concrete maintenance task difficult.
2. Use the repository Graphify skill before broad source exploration. Query
   the operation's call path and affected components, then inspect the cited
   source. If unavailable, report it and inspect a bounded set of files.
3. Record the exact entry point, domain types, port, adapter methods, existing
   tests, and reason the current code is difficult to read. Candidate areas
   include worker lifecycle, task transitions, and storage decoding; inspect
   them before claiming any specific defect.
4. Identify authorization, side effects, state/event transaction boundaries,
   concurrency protection, error variants, and recovery behavior to preserve.

## Refactor in buildable slices

| Slice | Change when justified | Evidence before committing |
| --- | --- | --- |
| Names and local flow | Clarify names, simplify branching, replace an opaque chain with direct steps. | Relevant tests and formatting pass; behavior is unchanged. |
| Domain behavior | Move cohesive transition rules into methods; introduce meaningful enum alternatives. | Legal and rejected transitions retain their tested behavior. |
| Use-case coordination | Keep the operation on a cohesive object when it owns the behavior; separate adapter I/O at the approved boundary. Add a service object only when it owns related dependencies and behavior. | Existing authorization, ordering, and errors are preserved. |
| Storage mapping | Introduce typed rows and fallible conversion where manual decoding obscures intent. | SQLite round trips, invalid values, and nullable fields are covered as relevant. |
| Atomic persistence | Clarify the operation's transaction ownership while retaining one explicit transaction or conditional write. | State/event atomicity and conflict handling remain correct. |

These are options, not mandatory layers or separate commits for every row.
Do not introduce a new public abstraction solely to follow the table.

Before each slice, locate existing behavior tests. Add focused regression
coverage only for missing behavior needed to assess the change. Keep each
slice buildable and commit it when its relevant checks pass, using a concrete
Conventional Commit subject under the working agreements.

For checked SQL macros, treat offline build support as a separate tooling
decision: prepare schema metadata, verify builds without `DATABASE_URL`, and
document how metadata stays synchronized. Do not switch query styles solely
to make a diff look more typed.

## Validation and completion

- Run formatting, the dependency boundary checker, and focused crate tests for
  the selected slice. Run Clippy as required by the commit hook.
- For persistence changes, use isolated SQLite fixtures and test the relevant
  rollback, restart, and concurrency behavior when affected.
- For worker lifecycle validation, use ordinary shell or fake-runner fixtures;
  do not start live model conversations or touch real user sessions.
- At the end of a planned refactoring batch, run `./scripts/check.sh`; the full
  script is also required before finishing a product milestone. Report any
  environmental restriction rather than claiming skipped checks passed.

A slice is complete when the operation reads clearly, relevant checks pass,
and behavior, dependencies, permissions, schema, wire contracts, and event
ordering remain unchanged. Record actual paths, changes, validation, and any
remaining work in the implementation handoff. Do not mark the overall plan
complete merely because one operation has been improved.
