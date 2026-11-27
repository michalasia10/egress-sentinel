//! Deterministic detection of basic secrets in normalized JSON data.

mod detect;

pub use detect::{Finding, SecretDetector};
