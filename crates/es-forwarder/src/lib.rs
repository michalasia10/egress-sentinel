//! Sends sanitized Sentry envelopes to named, policy-approved destinations.

mod forwarder;

pub use forwarder::{ForwardError, ForwardReceipt, Forwarder, SanitizedPayload};
