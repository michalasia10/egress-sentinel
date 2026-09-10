# es-detect

**Role:** deterministic detection of configured secret and PII categories.

It owns bounded regex, format, and entropy checks and returns categories and
locations, never matched raw values. It does not decide whether to redact,
quarantine, or forward; `es-policy` owns that decision.

It depends on `es-core` only among workspace crates.
