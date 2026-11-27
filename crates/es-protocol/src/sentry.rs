//! Bounded parsing of Sentry Envelopes.

use es_core::protocol::SourceProtocol;
use serde_json::Value;
use thiserror::Error;

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

/// A validated Sentry event normalized for policy evaluation.
#[derive(Clone, Debug, PartialEq)]
pub struct NormalizedEvent {
    source_protocol: SourceProtocol,
    event_type: EventType,
    data: Value,
}

impl NormalizedEvent {
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

/// Supported event categories in the Sentry Envelope ingress path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    /// A Sentry error event.
    Event,
    /// A Sentry transaction event.
    Transaction,
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

        let (header_line, remaining) = take_line(input)?;
        let header = parse_json(header_line)?;
        if !header.is_object() {
            return Err(SentryEnvelopeError::InvalidEnvelope);
        }
        let (item_header_line, payload_and_tail) = take_line(remaining)?;
        let item_header = parse_json(item_header_line)?;
        if !item_header.is_object() {
            return Err(SentryEnvelopeError::InvalidEnvelope);
        }
        let kind = item_header
            .get("type")
            .and_then(Value::as_str)
            .ok_or(SentryEnvelopeError::InvalidEnvelope)?;

        let event_type = match kind {
            "event" => EventType::Event,
            "transaction" => EventType::Transaction,
            "attachment" => return Err(SentryEnvelopeError::UnsupportedItem),
            "replay_event" | "replay_recording" => {
                return Err(SentryEnvelopeError::UnsupportedItem);
            }
            _ => return Err(SentryEnvelopeError::UnsupportedItem),
        };

        let payload = item_payload(&item_header, payload_and_tail)?;
        if payload.len() > limits.max_event_bytes {
            return Err(SentryEnvelopeError::EventTooLarge);
        }
        let data = parse_json(payload)?;
        if !data.is_object() {
            return Err(SentryEnvelopeError::InvalidEnvelope);
        }
        validate_fields(&data, limits)?;

        Ok(Self {
            header,
            event: NormalizedEvent {
                source_protocol: SourceProtocol::SentryEnvelope,
                event_type,
                data,
            },
        })
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

fn take_line(input: &[u8]) -> Result<(&[u8], &[u8]), SentryEnvelopeError> {
    let end = input
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(SentryEnvelopeError::InvalidEnvelope)?;
    let line = input[..end]
        .strip_suffix(b"\r")
        .unwrap_or(&input[..end]);
    if line.is_empty() {
        return Err(SentryEnvelopeError::InvalidEnvelope);
    }
    Ok((line, &input[end + 1..]))
}

fn parse_json(input: &[u8]) -> Result<Value, SentryEnvelopeError> {
    serde_json::from_slice(input).map_err(|_| SentryEnvelopeError::InvalidEnvelope)
}

fn item_payload<'a>(header: &Value, input: &'a [u8]) -> Result<&'a [u8], SentryEnvelopeError> {
    if let Some(length) = header.get("length") {
        let length = length
            .as_u64()
            .and_then(|length| usize::try_from(length).ok())
            .ok_or(SentryEnvelopeError::InvalidEnvelope)?;
        if input.len() < length {
            return Err(SentryEnvelopeError::InvalidEnvelope);
        }
        let (payload, tail) = input.split_at(length);
        if !tail.is_empty() && tail != b"\n" {
            return Err(SentryEnvelopeError::InvalidEnvelope);
        }
        Ok(payload)
    } else {
        let payload = input
            .strip_suffix(b"\n")
            .unwrap_or(input);
        if payload.contains(&b'\n') {
            return Err(SentryEnvelopeError::InvalidEnvelope);
        }
        Ok(payload)
    }
}

fn validate_fields(value: &Value, limits: EnvelopeLimits) -> Result<(), SentryEnvelopeError> {
    let mut pending = vec![value];
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
