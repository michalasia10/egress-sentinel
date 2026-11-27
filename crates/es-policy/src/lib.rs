//! Deterministically compiles and evaluates policy without performing I/O.

mod compile;
mod destination;
mod error;
mod evaluate;
mod event;
mod limits;
mod model;
mod rule;
mod source;

pub use compile::compile_yaml;
pub use error::{
    DestinationCause, DestinationError, DestinationField, EvaluationError, LimitsCause,
    LimitsError, LimitsField, PolicyError, RuleCause, RuleError, RuleField,
};
pub use evaluate::{Evaluation, EvaluationStatus};
pub use model::{
    Action, Destination, Limits, Match, Matcher, Policy, Protocol, Rule, RuleAction, Security,
};
