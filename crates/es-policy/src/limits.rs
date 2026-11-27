//! Policy limits and size parsing.

use crate::{
    error::PolicyError,
    model::Limits,
    source::{RawLimits, RawSize},
};

impl RawLimits {
    pub(super) fn compile(self) -> Result<Limits, PolicyError> {
        let max_event_size = self
            .max_event_size
            .map(parse_size)
            .transpose()?;
        validate_positive(
            self.max_string_field_length,
            "limits.max_string_field_length",
        )?;
        validate_positive(
            self.events_per_minute_per_project,
            "limits.events_per_minute_per_project",
        )?;
        Ok(Limits {
            max_event_size,
            max_string_field_length: self.max_string_field_length,
            events_per_minute_per_project: self.events_per_minute_per_project,
        })
    }
}

fn validate_positive(value: Option<u64>, field: &'static str) -> Result<(), PolicyError> {
    if value == Some(0) {
        return Err(PolicyError::Invalid {
            field,
            reason: "must be positive",
        });
    }
    Ok(())
}

fn parse_size(value: RawSize) -> Result<u64, PolicyError> {
    match value {
        RawSize::Bytes(bytes) if bytes > 0 => Ok(bytes),
        RawSize::Text(text) => {
            let text = text.trim().to_ascii_lowercase();
            let (number, multiplier) = text
                .strip_suffix("kb")
                .map(|v| (v, 1024))
                .or_else(|| {
                    text.strip_suffix("mb")
                        .map(|v| (v, 1024 * 1024))
                })
                .or_else(|| text.strip_suffix('b').map(|v| (v, 1)))
                .ok_or(PolicyError::Invalid {
                    field: "limits.max_event_size",
                    reason: "must use bytes, kb, or mb",
                })?;
            number
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .and_then(|value| value.checked_mul(multiplier))
                .ok_or(PolicyError::Invalid {
                    field: "limits.max_event_size",
                    reason: "must be a positive size",
                })
        }
        RawSize::Bytes(_) => Err(PolicyError::Invalid {
            field: "limits.max_event_size",
            reason: "must be positive",
        }),
    }
}
