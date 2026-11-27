# Rust readability and domain style

Approved on 2026-11-09. Apply this style to new and changed Rust code. Product
behavior remains defined by `PROJECT.md`, `TODO.md`, and the relevant milestone
architecture. This document adds coding guidance without changing crate or port
ownership.

## Read the use case from top to bottom

A reader should understand an operation's purpose, decisions, side effects,
and failure paths without first understanding SQLx or a provider CLI.

- Name operations with product vocabulary and verbs: `assign_worker`,
  `request_cancellation`, or `record_worker_exit`. Avoid vague `process_data`
  and `handle_everything` names.
- Keep a coherent level of detail within an operation. A use case should show
  its meaningful steps; the object responsible for a concept may own several
  steps when they form one operation.
- Prefer cohesive objects and meaningful methods over extracted private helper
  functions. Do not split an operation merely to reduce line count. A method
  may coordinate a longer sequence when the steps belong to the object's
  responsibility and the flow remains easy to follow.
- The operator likes iterators when they express readable domain operations.
  Prefer chains of clear predicates and transformations for collection queries.
  Use ordinary `let`, `if`, `match`, `for`, and `?` where they clarify control
  flow. Do not replace a chain with a loop solely because it is a chain; avoid
  nested closures and chains that obscure decisions or side effects.
- Return early for invalid inputs and unavailable operations. Make the normal
  path easy to follow without concealing important branches.
- Give behavior to the struct or enum that owns its state and invariant. Use a
  free function for a genuinely stateless transformation or shared operation
  when that is clearer; avoid private helpers that only forward arguments,
  rename one expression, or hide part of a cohesive object's workflow. There is
  no fixed line-count limit; use length as a prompt to inspect responsibility,
  not as a reason to extract code.
- Comments explain reasons, invariants, and ordering constraints. Names and
  code should explain routine steps.

## Domain objects: structs, enums, and methods

Treat Rust structs and enums as the workspace's domain objects. Make them the
default home for related state and behavior: put methods beside the state and
rules they govern, and use private fields when unrestricted mutation could
break an invariant. Constructors and methods should make valid transitions
easy to express and invalid transitions hard to represent.

Model meaningful domain concepts with semantic types such as newtypes and
value objects instead of stringly typed values or primitive IDs that can be
confused with one another. Put the invariant in the type's constructor and
methods, then convert to strings or other primitive representations at
protocol and persistence boundaries. Do not add wrappers for values that have
no distinct meaning or invariant.

Structs should own their fields by default. Prefer `String`, `Vec<T>`, and
owned domain values so a struct owns its data and other code borrows from it.
Borrowed fields such as `&str` or `&[T]` are appropriate when borrowing is an
intentional part of the type's purpose and its lifetime makes the design
clearer; do not add lifetime parameters just to avoid owning ordinary data.

Use methods for meaningful domain behavior, state transitions, and operations
that belong to the object. Methods need not be tiny: keep one cohesive
responsibility and let the object's public operation show its sequence. Keep
external effects in the approved adapters and persistence boundary. Compose
objects into readable use cases instead of scattering domain rules across
callers.

Use enums for states, commands, alternatives, and meaningful error categories.
Variants may carry data when that prevents invalid combinations. Prefer named
fields and explicit options over ambiguous boolean arguments or positional
tuples. Introduce types such as `TaskId` or `WorkerId` when they clarify meaning,
enforce an invariant, or prevent mixing identifiers; avoid wrappers that add
only ceremony.

Prefer composition. Define traits for real boundaries or shared behavior, not
for every struct. Preserve the approved ports in `wy-contracts`, including the
async, object-safe `StateStore`; do not replace them with concrete adapter
dependencies in application code. Keep generics, lifetimes, and macros as
simple as the responsibility permits.

Use a design pattern when it names a real problem in this code and makes the
solution easier to follow. Do not add a pattern, service layer, trait, builder,
or helper just to make the code look more structured. Prefer the smallest
design that makes the rule and its owner clear.

## Examples: make intent visible

These examples show the direction of the style, not mandatory APIs or a rule
that every `match`, loop, or helper should be rewritten. Preserve meaningful
context, validation, and error distinctions when simplifying code.

### Give arguments meaning at the call site

Avoid a run of booleans whose meaning depends on remembering parameter order:

```rust,ignore
create_worker(project_id, task_id, true, false);
```

Use a request type and named fields when the options form one operation:

```rust,ignore
create_worker(CreateWorkerRequest {
    project_id,
    task_id,
    start_agent: true,
    reuse_worktree: false,
});
```

For a small, stable choice, an enum may be clearer than a request struct:

```rust,ignore
select_diff(DiffScope::WorkingTree);
```

### Keep the normal path easy to see

Avoid nesting the actual operation under several guards:

```rust,ignore
if project.is_some() {
    if worker.is_available() {
        if policy.allows_start() {
            start_run(worker)?;
        }
    }
}
```

Make rejection paths explicit, then let the authorized operation read in order:

```rust,ignore
let Some(project) = project else {
    return Err(StartError::MissingProject);
};
if !worker.is_available() {
    return Err(StartError::WorkerUnavailable);
}
if !policy.allows_start() {
    return Err(StartError::Denied);
}

start_run(project, worker)?;
```

Use the project's real error types and preserve every policy check; early
returns are a readability tool, not permission to drop a branch.

### Prefer meaningful object operations to micro-functions

Avoid extracting trivial accessors and wrappers that only shorten the visible
operation:

```rust,ignore
fn gateway_model(settings: &GatewaySettings) -> &str {
    settings.model.as_str()
}

fn gateway_kind(settings: &GatewaySettings) -> GatewayRunnerKind {
    settings.kind
}

fn gateway_is_claude(settings: &GatewaySettings) -> bool {
    settings.kind == GatewayRunnerKind::Claude
}
```

Keep provider behavior on the object that owns those values, and keep the
ordered provisioning operation on `RunHome`:

```rust,ignore
impl GatewaySettings {
    fn provider_environment(&self) -> Vec<(&'static str, String)> {
        match self.kind {
            GatewayRunnerKind::Codex => vec![],
            GatewayRunnerKind::Claude => vec![
                ("ANTHROPIC_BASE_URL", format!("http://{}", self.binding.address())),
                ("ANTHROPIC_MODEL", self.model.clone()),
            ],
        }
    }
}

impl RunHome {
    fn configure_gateway(&mut self, settings: GatewaySettings, client_key: &str) -> Result<()> {
        self.validate()?;
        if !matches!(self.gateway, GatewayHomeState::Unconfigured) {
            return Err(denied("gateway HOME is already configured or preparation failed"));
        }
        let contents = settings.configuration()?;

        // Partial setup must remain non-retryable.
        self.gateway = GatewayHomeState::Preparing;
        self.write_new("model-gateway.key", format!("{client_key}\\n").as_bytes())?;
        let (directory, relative_path) = match settings.kind {
            GatewayRunnerKind::Codex => (".codex", ".codex/config.toml"),
            GatewayRunnerKind::Claude => (".claude", ".claude/settings.json"),
        };
        self.ensure_provider_directory(directory)?;
        let configuration = self.write_provider_configuration(relative_path, &contents)?;
        self.gateway = GatewayHomeState::Configured(GatewayHome {
            settings,
            configuration,
        });
        Ok(())
    }
}
```

The example is illustrative; it is not a request to add these exact methods.
The current `GatewaySettings` and `RunHome::configure_gateway` already show
this object-centered shape; provider configuration serialization is also
behavior on `GatewaySettings`. Keep their security-sensitive ordering visible.
Extract behavior when another object owns it or when a separate operation has
its own useful contract, not to meet a preferred function length. A cohesive
method may be longer than a helper-oriented style guide would recommend.

### Let a domain object own its rule

Avoid checking and mutating the same object's invariant at each call site:

```rust,ignore
if run.status() == RunStatus::Pending {
    run.set_status(RunStatus::Running);
}
```

Give the state transition to the object that owns it:

```rust,ignore
run.start()?;
```

```rust,ignore
impl Run {
    fn start(&mut self) -> Result<(), RunError> {
        if self.status != RunStatus::Pending {
            return Err(RunError::CannotStartFrom(self.status));
        }

        self.status = RunStatus::Running;
        Ok(())
    }
}
```

Keep the method focused on the domain transition. The use case remains
responsible for authorization, persistence, and other effects.

### Propagate errors without hiding useful context

When a function only forwards an error, avoid spelling out both `Result`
branches:

```rust,ignore
let config = match load_config(path) {
    Ok(config) => config,
    Err(error) => return Err(error),
};
```

Use `?` for that case:

```rust,ignore
let config = load_config(path)?;
```

When the boundary needs to add operation context or translate into a domain
error, keep that conversion visible rather than flattening the error to text.

### Use iterators for readable collection decisions

Avoid a manual accumulator when the operation is plainly a filter and map:

```rust,ignore
let mut worker_ids = Vec::new();
for worker in workers {
    if worker.is_active() {
        worker_ids.push(worker.id().clone());
    }
}
```

Prefer a domain-named predicate and a direct pipeline:

```rust,ignore
let worker_ids = workers
    .iter()
    .filter(|worker| worker.is_active())
    .map(|worker| worker.id().clone())
    .collect::<Vec<_>>();
```

Use a `for` loop when it makes side effects, early exits, or several decisions
clearer. Avoid deeply nested closures and chains whose steps hide those effects.

### Keep persistence conversion explicit

Avoid silently mapping unknown stored values to a valid state:

```rust,ignore
let status = match stored_status.as_str() {
    "active" => RunStatus::Active,
    _ => RunStatus::Pending,
};
```

Reject values the application does not understand:

```rust,ignore
let status = RunStatus::try_from(stored_status.as_str())?;
```

Keep the conversion adapter-local and fallible. The actual error should identify
the invalid persisted value without changing schema or recovery behavior.

### Keep atomic work in one visible transaction

Do not make a state change and its event two unrelated writes:

```rust,ignore
save_run(&pool, &run).await?;
append_event(&pool, &event).await?;
```

Keep both writes under the same transaction when they form one atomic action:

```rust,ignore
let mut transaction = pool.begin().await?;
save_run(&mut transaction, &run).await?;
append_event(&mut transaction, &event).await?;
transaction.commit().await?;
```

The operation signatures and caller should make it clear that both writes share
the same transaction. Preserve conditional updates, affected-row checks, and
concurrency control where the operation requires them.

### Comments should preserve non-obvious knowledge

Avoid comments that merely repeat the next line:

```rust,ignore
// Increment the sequence.
sequence += 1;
```

Explain why an unusual order or constraint exists:

```rust,ignore
// Persist the claim before cleanup so cancellation leaves an uncertain
// attempt that recovery will not retry blindly.
persist_stop_claim(&mut transaction).await?;
```

Do not impose line-count limits for functions or files. A long method or
highly connected type is a prompt to inspect its responsibilities, not proof
that extraction is needed. Give a distinct responsibility to its owning object
or a cohesive module; use a free function only when its stateless/shared nature
makes that the clearest home.

## Responsibilities in this workspace

| Responsibility | Location | Guideline |
| --- | --- | --- |
| Domain values and state transitions | `wy-domain` | Structs/enums and methods; no SQLx, Tokio, or I/O dependencies. |
| Ports | `wy-contracts` | Describe capabilities and operations using domain/contract types. |
| Persistence | `wy-storage` | SQLx pools, rows, SQL, conversions, migrations, and atomic writes. |
| Use cases and policy | `wy-orchestrator`, with existing daemon wiring | Coordinate domain behavior and ports; keep authorization visible. |
| Host processes and provider flags | Existing adapters | Encapsulate subprocess and vendor details. |
| TUI | `wy-tui` | Preserve the TEA model, gateway boundary, and render-only components. |

A small service struct may own the dependencies needed for a use case. Add it
when it gives those dependencies and operations a coherent home, not as a
mandatory layer for every operation. Likewise, a named storage repository may
organize SQL inside `wy-storage` without introducing new workspace boundaries
or bypassing `StateStore`.

Keep `lib.rs` limited to crate documentation, module declarations, and exports.
Split implementations by responsibility, not by an arbitrary line count.

## SQLx and SQLite

Use existing SQLx facilities before adding another persistence abstraction:

- Use `#[derive(sqlx::FromRow)]` with `query_as` for named row structs where it
  removes repetitive column extraction. Select explicit columns and bind values.
- `query_as` is checked at runtime. `query_as!` checks SQL during compilation
  and does not use `FromRow`. If adopting checked macros, supply a build-time
  schema or checked-in offline metadata and its maintenance workflow. Preserve
  builds/tests without a developer database or globally installed SQLx CLI.
- Keep short queries near the adapter method. Consider `query_file_as!` for
  longer static SQL when checked macros are already supported; otherwise
  `include_str!` with `query_as` can load a SQL file with runtime validation.
  Do not move every query into a separate file by default.
- Use adapter-local row structs when database representation differs from the
  domain. Convert fallibly with `TryFrom` when decoding requires validation.
  Do not duplicate types where direct mapping is clear and safe.
- Keep SQLx derives on adapter-local types. For an adapter-local newtype,
  `#[derive(sqlx::Type)]` with `#[sqlx(transparent)]` can reuse the inner SQL
  representation. Do not add SQLx to `wy-domain` to derive it on domain IDs.
- Define stored enum representations explicitly. Reject unknown persisted
  values; do not silently choose a default state. Enums carrying data may need
  an explicit multi-column or serialized representation.
- Name persistence methods by their operation, such as `find_task` or
  `record_worker_exit`. Keep transaction ownership explicit. Every SQL
  operation in an atomic workflow must use the same transaction rather than
  independently acquiring connections from the pool.
- Preserve atomic state/event writes. A load-modify-save sequence alone is not
  concurrency control: use the existing transaction, conditional update, or
  version check as required, and verify affected rows where relevant.

## Errors, tests, and review

Use `Result` and `?` for expected failures. Use domain error enums for failures
callers need to distinguish, and preserve useful operation context at adapter
boundaries. Do not flatten all failures into strings or add production
`unwrap()` calls to shorten the happy path.

Test observable transitions, rejected operations, persistence, and failure
behavior. Preserve default-deny authorization, capability checks, restart
recovery, and wire compatibility. Reuse existing tests; add regression tests
for uncovered behavior or risks, not tests of private helper decomposition.

In production code, do not use `unwrap()` or `expect()` to turn an expected
failure into a panic. In tests, use them when they keep setup direct and the
assertion focused. Do not suppress an error with a default value unless that
default is the actual domain behavior.

For agents reviewing a change:

1. Can the main operation be understood as a sequence of domain steps?
2. Do structs own related data and methods protect meaningful invariants?
3. Do enums and argument names make alternatives clear at the call site?
4. Are I/O, authorization, and transaction boundaries easy to locate?
5. Does each abstraction reduce the reader's work?
6. Do tests and checks support the claimed preservation of behavior?

## Reading and rationale

- [Rust Book: structs](https://doc.rust-lang.org/stable/book/ch05-00-structs.html)
  explains data modeling with structs and methods.
- [Rust Book: modularity and error handling](https://doc.rust-lang.org/book/ch12-03-improving-error-handling-and-modularity.html)
  demonstrates separating responsibilities and simplifying entry points.
- [Rust API Guidelines: naming](https://rust-lang.github.io/api-guidelines/naming.html)
  and [type safety](https://rust-lang.github.io/api-guidelines/type-safety.html)
  support predictable names and meaningful argument types.
- [Google Rust Style Guide](https://google.github.io/styleguide/rustguide.html)
  provides readability guidance. Its platform-specific rules are not adopted
  wholesale; this project continues to use Tokio and async Rust.
- [Eclipse Ankaios Rust coding guidelines](https://eclipse-ankaios.github.io/ankaios/0.3/development/rust-coding-guidelines/)
  offers practical examples for error propagation, control flow, and sync/async
  boundaries. Apply those ideas when they agree with this workspace's ports,
  error semantics, and readability preferences.
- [Martin Fowler: Refactoring](https://martinfowler.com/books/refactoring.html)
  describes small behavior-preserving transformations and code smells as
  signals to inspect, not automatic reasons to rewrite code.
- [Matthias Endler: programming paradigms](https://corrode.dev/blog/paradigms/)
  discusses combining procedural, object-oriented, and functional techniques.
- SQLx documentation: [FromRow](https://docs.rs/sqlx/0.9.0/sqlx/trait.FromRow.html),
  [query_as!](https://docs.rs/sqlx/0.9.0/sqlx/macro.query_as.html),
  [query_file_as!](https://docs.rs/sqlx/0.9.0/sqlx/macro.query_file_as.html), and
  [Type](https://docs.rs/sqlx/0.9.0/sqlx/trait.Type.html).

The workspace organization above is a project decision informed by these
sources, not an architecture prescribed by SQLx.
