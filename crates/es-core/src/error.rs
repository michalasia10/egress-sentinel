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
}
