//! Deterministic detection of basic secrets in normalized JSON data.

mod detect;
mod validators;

pub use detect::{Finding, SecretDetector};
