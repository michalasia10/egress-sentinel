# es-policy

**Role:** turn YAML policy into a validated, compiled, deterministic evaluator.

It owns policy schema validation, rule ordering, matcher compilation, action
semantics, destination declarations, and explainable evaluation summaries. It
returns decisions and transformation instructions; it never fetches key material,
forwards telemetry, writes audit rows, or parses transport-specific requests.

It depends on `es-core` and policy-format libraries only.
