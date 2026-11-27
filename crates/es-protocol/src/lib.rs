//! Bounded parsing and normalization of supported telemetry protocols.

mod sentry;

pub use sentry::{EnvelopeLimits, EventType, NormalizedEvent, SentryEnvelope, SentryEnvelopeError};
