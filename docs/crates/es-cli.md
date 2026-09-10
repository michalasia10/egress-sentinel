# es-cli

**Role:** human and CI-facing command-line adapter.

It provides `validate`, `test`, and `explain` commands over the same policy
models and service operations. It may render fixture diffs only when the fixture
is local and the user explicitly requests it; ordinary output must avoid raw
secrets.

It depends on `es-service` and CLI libraries. It has no policy or forwarding
logic of its own.
