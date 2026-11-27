use serde_json::Value;
use thiserror::Error;

use super::event::{EventType, NormalizedEvent};

/// Resource bounds applied before and during envelope normalization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeLimits {
    /// Maximum complete request size in bytes.
    pub max_request_bytes: usize,
    /// Maximum single event payload size in bytes.
    pub max_event_bytes: usize,
    /// Maximum number of JSON object fields and array elements in an event.
    pub max_fields: usize,
    /// Maximum encoded size of any JSON string, including object keys.
    pub max_field_bytes: usize,
}

impl Default for EnvelopeLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: 1_048_576,
            max_event_bytes: 524_288,
            max_fields: 16_384,
            max_field_bytes: 65_536,
        }
    }
}

/// A parsed envelope containing one supported event.
#[derive(Clone, Debug, PartialEq)]
pub struct SentryEnvelope {
    header: Value,
    event: NormalizedEvent,
}

impl SentryEnvelope {
    /// Parses one Sentry Envelope while enforcing request, event, and field bounds.
    pub fn parse(input: &[u8], limits: EnvelopeLimits) -> Result<Self, SentryEnvelopeError> {
        if input.len() > limits.max_request_bytes {
            return Err(SentryEnvelopeError::RequestTooLarge);
        }

        let mut reader = EnvelopeReader::new(input);
        let header = reader.json_object()?;
        let item_header = reader.json_object()?;
        let event_type = EventType::from_item_header(&item_header)?;
        let payload = reader.event_payload(item_header.get("length"))?;
        if payload.len() > limits.max_event_bytes {
            return Err(SentryEnvelopeError::EventTooLarge);
        }
        let event = NormalizedEvent::parse(event_type, payload, limits)?;

        Ok(Self { header, event })
    }

    /// Returns the envelope header metadata.
    pub fn header(&self) -> &Value {
        &self.header
    }

    /// Returns the normalized event.
    pub fn event(&self) -> &NormalizedEvent {
        &self.event
    }
}

/// Safe parsing failures. These variants never contain input bytes or parser messages.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SentryEnvelopeError {
    /// The complete request exceeded its configured bound.
    #[error("request exceeds the configured size limit")]
    RequestTooLarge,
    /// The event payload exceeded its configured bound.
    #[error("event exceeds the configured size limit")]
    EventTooLarge,
    /// The envelope was malformed, invalid JSON, or truncated.
    #[error("invalid Sentry envelope")]
    InvalidEnvelope,
    /// The envelope contains an item type this ingress path does not accept.
    #[error("unsupported Sentry envelope item")]
    UnsupportedItem,
    /// The event contains too many fields or an oversized string field.
    #[error("event exceeds the configured field limits")]
    FieldsTooLarge,
}

/// Reads envelope components while owning the current position in the request bytes.
struct EnvelopeReader<'a> {
    remaining: &'a [u8],
}

impl<'a> EnvelopeReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { remaining: input }
    }

    fn json_object(&mut self) -> Result<Value, SentryEnvelopeError> {
        let line_end = self
            .remaining
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or(SentryEnvelopeError::InvalidEnvelope)?;
        let line = self.remaining[..line_end]
            .strip_suffix(b"\r")
            .unwrap_or(&self.remaining[..line_end]);
        if line.is_empty() {
            return Err(SentryEnvelopeError::InvalidEnvelope);
        }

        self.remaining = &self.remaining[line_end + 1..];
        let value: Value =
            serde_json::from_slice(line).map_err(|_| SentryEnvelopeError::InvalidEnvelope)?;
        if !value.is_object() {
            return Err(SentryEnvelopeError::InvalidEnvelope);
        }
        Ok(value)
    }

    fn event_payload(
        &mut self,
        declared_length: Option<&Value>,
    ) -> Result<&'a [u8], SentryEnvelopeError> {
        if let Some(declared_length) = declared_length {
            let length = declared_length
                .as_u64()
                .and_then(|length| usize::try_from(length).ok())
                .ok_or(SentryEnvelopeError::InvalidEnvelope)?;
            if self.remaining.len() < length {
                return Err(SentryEnvelopeError::InvalidEnvelope);
            }

            let (payload, tail) = self.remaining.split_at(length);
            if !tail.is_empty() && tail != b"\n" {
                return Err(SentryEnvelopeError::InvalidEnvelope);
            }
            return Ok(payload);
        }

        let payload = self
            .remaining
            .strip_suffix(b"\n")
            .unwrap_or(self.remaining);
        if payload.contains(&b'\n') {
            return Err(SentryEnvelopeError::InvalidEnvelope);
        }
        Ok(payload)
    }
}
