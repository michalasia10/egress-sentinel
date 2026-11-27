# es-detect

**Role:** deterministic detection of configured secret and PII categories.

It owns bounded regex, format, and entropy checks and returns categories and
locations, never matched raw values. It does not decide whether to redact,
quarantine, or forward; `es-policy` owns that decision.

Keep traversal of normalized data in the detector and secret-format matching
in a single provider-pattern catalog. Each rule maps to a closed detection
category; the detector combines all matching categories with safe field
locations. Validate JWT structure after the pattern prefilter. Never return
matched text or decoded secret material.

Provider patterns are adapted from [adventurewave-labs/secret-scan](https://github.com/adventurewave-labs/secret-scan),
commit `2fbdbd35e807c8c24d6af87d00d80f0595e2ca69` (MIT). Generic low-confidence
and obfuscation rules are excluded from this detector's current scope.

It depends on `es-core` only among workspace crates.
