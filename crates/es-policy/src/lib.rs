//! Deterministically compiles and evaluates policy without performing I/O.

mod compile;
mod error;
mod evaluate;
mod model;
mod source;

pub use compile::compile_yaml;
pub use error::PolicyError;
pub use model::{Action, Destination, Limits, Match, Matcher, Policy, Protocol, Rule, Security};
