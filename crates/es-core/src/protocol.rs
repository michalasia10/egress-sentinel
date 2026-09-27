//! Shared vocabulary for source telemetry protocols.

/// The protocol through which telemetry entered the gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourceProtocol {
    /// The Sentry envelope protocol.
    SentryEnvelope,
}
