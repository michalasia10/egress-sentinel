//! Bounded parsing of Sentry Envelopes.

mod envelope;
mod event;

pub use envelope::{EnvelopeLimits, SentryEnvelope, SentryEnvelopeError};
pub use event::{EventType, NormalizedEvent};
