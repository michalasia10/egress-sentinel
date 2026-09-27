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

    /// A policy decision was created with the ingress-only rejected outcome.
    #[error("a policy decision cannot have a rejected outcome")]
    RejectedOutcomeForPolicyDecision,
}
