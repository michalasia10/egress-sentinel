# es-detect

**Role:** deterministic detection of configured secret and PII categories.

It owns bounded regex, format, and entropy checks and returns categories and
locations, never matched raw values. It does not decide whether to redact,
quarantine, or forward; `es-policy` owns that decision.

Keep traversal of normalized data in the detector and secret-format matching
in category-specific validators. Each validator owns the rules for one
category; the detector combines their category-only results with safe field
locations.

It depends on `es-core` only among workspace crates.
