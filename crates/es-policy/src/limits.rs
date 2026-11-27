//! Policy limits and size parsing.

use crate::{
    error::{LimitsCause, LimitsError, LimitsField, PolicyError},
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
            LimitsField::MaxStringFieldLength,
        )?;
        validate_positive(
            self.events_per_minute_per_project,
            LimitsField::EventsPerMinutePerProject,
        )?;
        Ok(Limits {
            max_event_size,
            max_string_field_length: self.max_string_field_length,
            events_per_minute_per_project: self.events_per_minute_per_project,
        })
    }
}

fn validate_positive(value: Option<u64>, field: LimitsField) -> Result<(), PolicyError> {
    if value == Some(0) {
        return Err(PolicyError::Limits(LimitsError::Invalid {
            field,
            cause: LimitsCause::MustBePositive,
        }));
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
                .ok_or(PolicyError::Limits(LimitsError::Invalid {
                    field: LimitsField::MaxEventSize,
                    cause: LimitsCause::InvalidSizeUnit,
                }))?;
            number
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .and_then(|value| value.checked_mul(multiplier))
                .ok_or(PolicyError::Limits(LimitsError::Invalid {
                    field: LimitsField::MaxEventSize,
                    cause: LimitsCause::InvalidSize,
                }))
        }
        RawSize::Bytes(_) => Err(PolicyError::Limits(LimitsError::Invalid {
            field: LimitsField::MaxEventSize,
            cause: LimitsCause::MustBePositive,
        })),
    }
}
