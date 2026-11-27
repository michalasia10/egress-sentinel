//! Policy compilation errors.
use thiserror::Error;
#[derive(Debug, Error, PartialEq, Eq)]
/// Safe errors produced while parsing and validating a policy.
pub enum PolicyError {
    #[error("policy document is malformed")]
    /// The YAML document could not be parsed against the policy schema.
    Malformed,
    #[error("policy field `{field}` is invalid: {reason}")]
    /// A field has a value that violates the policy contract.
    Invalid {
        /// Safe field name, without the field value.
        field: &'static str,
        /// Safe reason, without the field value.
        reason: &'static str,
    },
    #[error("policy field `{field}` contains a duplicate identifier")]
    /// An identifier appears more than once in its namespace.
    Duplicate {
        /// Safe field name, without the duplicate value.
        field: &'static str,
    },
    #[error("policy reference `{field}` is unresolved")]
    /// A reference does not resolve to a declared policy object.
    Unresolved {
        /// Safe field name, without the unresolved value.
        field: &'static str,
    },
}
