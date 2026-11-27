use es_core::protocol::SourceProtocol;
use serde_json::Value;

use super::envelope::{EnvelopeLimits, SentryEnvelopeError};

/// Supported event categories in the Sentry Envelope ingress path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    /// A Sentry error event.
    Event,
    /// A Sentry transaction.
    Transaction,
}

impl EventType {
    pub(super) fn from_item_header(header: &Value) -> Result<Self, SentryEnvelopeError> {
        match header
            .get("type")
            .and_then(Value::as_str)
        {
            Some("event") => Ok(Self::Event),
            Some("transaction") => Ok(Self::Transaction),
            Some(_) => Err(SentryEnvelopeError::UnsupportedItem),
            None => Err(SentryEnvelopeError::InvalidEnvelope),
        }
    }
}

/// A validated Sentry event normalized for policy evaluation.
#[derive(Clone, Debug, PartialEq)]
pub struct NormalizedEvent {
    source_protocol: SourceProtocol,
    event_type: EventType,
    data: Value,
}

impl NormalizedEvent {
    pub(super) fn parse(
        event_type: EventType,
        payload: &[u8],
        limits: EnvelopeLimits,
    ) -> Result<Self, SentryEnvelopeError> {
        let data: Value =
            serde_json::from_slice(payload).map_err(|_| SentryEnvelopeError::InvalidEnvelope)?;
        if !data.is_object() {
            return Err(SentryEnvelopeError::InvalidEnvelope);
        }

        let event = Self {
            source_protocol: SourceProtocol::SentryEnvelope,
            event_type,
            data,
        };
        event.validate_fields(limits)?;
        Ok(event)
    }

    fn validate_fields(&self, limits: EnvelopeLimits) -> Result<(), SentryEnvelopeError> {
        let mut pending = vec![&self.data];
        let mut fields = 0usize;

        while let Some(value) = pending.pop() {
            match value {
                Value::Object(object) => {
                    fields = fields
                        .checked_add(object.len())
                        .ok_or(SentryEnvelopeError::FieldsTooLarge)?;
                    if fields > limits.max_fields
                        || object
                            .keys()
                            .any(|key| key.len() > limits.max_field_bytes)
                    {
                        return Err(SentryEnvelopeError::FieldsTooLarge);
                    }
                    pending.extend(object.values());
                }
                Value::Array(array) => {
                    fields = fields
                        .checked_add(array.len())
                        .ok_or(SentryEnvelopeError::FieldsTooLarge)?;
                    if fields > limits.max_fields {
                        return Err(SentryEnvelopeError::FieldsTooLarge);
                    }
                    pending.extend(array);
                }
                Value::String(string) if string.len() > limits.max_field_bytes => {
                    return Err(SentryEnvelopeError::FieldsTooLarge);
                }
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            }
        }

        Ok(())
    }

    /// Returns the protocol that carried this event.
    pub fn source_protocol(&self) -> SourceProtocol {
        self.source_protocol
    }

    /// Returns whether the event is an error event or a transaction.
    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    /// Returns the normalized event data.
    pub fn data(&self) -> &Value {
        &self.data
    }
}
