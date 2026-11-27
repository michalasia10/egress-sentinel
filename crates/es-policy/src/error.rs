//! Policy compilation errors.

use std::fmt::{self, Display, Formatter};

use thiserror::Error;

use crate::model::Action;

/// Safe errors produced while parsing and validating a policy.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// The YAML document could not be parsed against the policy schema.
    #[error("policy document is malformed")]
    Malformed,
    /// The policy format version is unsupported.
    #[error("policy field `version` is invalid: unsupported version")]
    InvalidVersion,
    /// A destination declaration failed its domain validation.
    #[error("{0}")]
    Destination(DestinationError),
    /// A rule declaration failed its domain validation.
    #[error("{0}")]
    Rule(RuleError),
    /// A limits declaration failed its domain validation.
    #[error("{0}")]
    Limits(LimitsError),
}

/// Failures that prevent a policy evaluation from completing.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EvaluationError {
    /// A matching HMAC rule referred to key material absent from local configuration.
    #[error("local key material for a matching policy rule is unavailable")]
    MissingKey,
    /// The HMAC implementation rejected key material.
    #[error("local key material for a matching policy rule is invalid")]
    InvalidKey,
}

/// Errors owned by a destination declaration or catalog.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DestinationError {
    /// A destination field has an invalid value.
    #[error("policy field `{field}` is invalid: {cause}")]
    Invalid {
        /// The invalid destination field.
        field: DestinationField,
        /// The safe reason the field is invalid.
        cause: DestinationCause,
    },
    /// A destination ID was already declared.
    #[error("policy field `destinations.id` contains a duplicate identifier")]
    DuplicateId,
}

/// Fields that belong to a destination declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationField {
    /// The destination collection.
    Collection,
    /// The destination ID.
    Id,
    /// The destination protocol.
    Protocol,
    /// The destination host allow-list.
    AllowedHosts,
}

impl Display for DestinationField {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Collection => "destinations",
            Self::Id => "destinations.id",
            Self::Protocol => "destinations.protocol",
            Self::AllowedHosts => "destinations.allowed_hosts",
        })
    }
}

/// Safe causes for destination validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DestinationCause {
    /// A required value or collection was empty.
    #[error("must not be empty")]
    Empty,
    /// The protocol is not supported.
    #[error("unsupported protocol")]
    UnsupportedProtocol,
    /// The allow-list contains a non-DNS hostname.
    #[error("must contain valid host names")]
    InvalidHostname,
}

/// Errors owned by a rule declaration or catalog.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleError {
    /// A rule field has an invalid value or relationship.
    #[error("policy field `{field}` is invalid: {cause}")]
    Invalid {
        /// The invalid rule field.
        field: RuleField,
        /// The safe reason the field is invalid.
        cause: RuleCause,
    },
    /// A rule ID was already declared.
    #[error("policy field `rules.id` contains a duplicate identifier")]
    DuplicateId,
    /// A route destination does not resolve to a declared destination.
    #[error("policy reference `rules.destination` is unresolved")]
    UnresolvedDestination,
}

/// Fields that belong to a rule declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleField {
    /// The rule collection.
    Collection,
    /// The rule ID.
    Id,
    /// The rule matcher object.
    Matcher,
    /// The JSONPath selector.
    JsonPath,
    /// The JSONPath selector list.
    Paths,
    /// The object key selector list.
    KeyMatches,
    /// The action name.
    Action,
    /// The local key reference.
    KeyRef,
    /// The replacement marker.
    Marker,
    /// The mask preserve count.
    Preserve,
    /// The route destination reference.
    Destination,
}

impl Display for RuleField {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Collection => "rules",
            Self::Id => "rules.id",
            Self::Matcher => "rules",
            Self::JsonPath => "rules.match.json_path",
            Self::Paths => "rules.match.paths",
            Self::KeyMatches => "rules.match.key_matches",
            Self::Action => "rules.action",
            Self::KeyRef => "rules.key_ref",
            Self::Marker => "rules.marker",
            Self::Preserve => "rules.preserve",
            Self::Destination => "rules.destination",
        })
    }
}

/// Safe causes for rule validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleCause {
    /// A required value or collection was empty.
    #[error("must not be empty")]
    Empty,
    /// A rule matcher is missing or has conflicting variants.
    #[error("must contain exactly one valid matcher")]
    InvalidMatcher,
    /// A JSONPath selector could not be compiled.
    #[error("must be a valid JSONPath expression")]
    InvalidJsonPath,
    /// A parameter is required by the selected action.
    #[error("required only for {0}")]
    RequiredForAction(Action),
    /// A parameter is not valid for the selected action.
    #[error("not allowed for {0}")]
    ForbiddenForAction(Action),
    /// A numeric parameter must be positive.
    #[error("must be positive")]
    MustBePositive,
    /// A size must use one of the supported units.
    #[error("must use bytes, kb, or mb")]
    InvalidSizeUnit,
    /// A size is zero, malformed, or overflows its numeric representation.
    #[error("must be a positive size")]
    InvalidSize,
    /// An action name is not supported.
    #[error("unsupported action")]
    UnsupportedAction,
}

/// Errors owned by policy limits.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LimitsError {
    /// A limits field has an invalid value.
    #[error("policy field `{field}` is invalid: {cause}")]
    Invalid {
        /// The invalid limits field.
        field: LimitsField,
        /// The safe reason the field is invalid.
        cause: LimitsCause,
    },
}

/// Fields that belong to the limits declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitsField {
    /// The event size limit.
    MaxEventSize,
    /// The string field length limit.
    MaxStringFieldLength,
    /// The project event rate limit.
    EventsPerMinutePerProject,
}

impl Display for LimitsField {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MaxEventSize => "limits.max_event_size",
            Self::MaxStringFieldLength => "limits.max_string_field_length",
            Self::EventsPerMinutePerProject => "limits.events_per_minute_per_project",
        })
    }
}

/// Safe causes for limits validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LimitsCause {
    /// A numeric limit must be positive.
    #[error("must be positive")]
    MustBePositive,
    /// A size uses an unsupported unit.
    #[error("must use bytes, kb, or mb")]
    InvalidSizeUnit,
    /// A size is malformed, zero, or overflows.
    #[error("must be a positive size")]
    InvalidSize,
}
