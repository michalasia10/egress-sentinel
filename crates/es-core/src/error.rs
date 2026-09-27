//! Domain errors returned by `es-core`.

use thiserror::Error;

/// Errors that can occur while constructing core domain values.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    /// A project identifier was empty.
    #[error("project identifier cannot be empty")]
    EmptyProjectId,

    /// A destination identifier was empty.
    #[error("destination identifier cannot be empty")]
    EmptyDestinationId,

    /// A policy version was zero.
    #[error("policy version must be a positive value")]
    PolicyVersionNotPositive,

    /// A policy digest was empty.
    #[error("policy digest cannot be empty")]
    EmptyPolicyDigest,

    /// A policy rule identifier was empty.
    #[error("rule identifier cannot be empty")]
    EmptyRuleId,

    /// A policy-terminated decision had no final terminal action.
    #[error("a policy-terminated decision requires a final terminal action")]
    TerminatedByPolicyWithoutTerminalAction,

    /// A forwarded or failed decision ended with a terminal policy action.
    #[error("a forwarded or failed decision cannot end with a terminal action")]
    DirectResolutionWithTerminalAction,

    /// A terminal policy action occurred before the final applied rule.
    #[error("a terminal action must be the final applied rule")]
    NonFinalTerminalAction,
}
