//! Categories of sensitive values recognized by detection components.

/// A category of sensitive value detected in a payload.
///
/// This classification contains no matched value or detection implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DetectionCategory {
    /// A JSON Web Token.
    Jwt,
    /// An API key.
    ApiKey,
    /// A private cryptographic key.
    PrivateKey,
    /// A connection string containing connection credentials or endpoints.
    ConnectionString,
}
