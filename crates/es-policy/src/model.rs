//! Validated policy model.

use serde_json_path::JsonPath;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroU64;
/// A validated policy ready for activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Monotonically assigned policy format version.
    pub version: u64,
    /// Named, approved outbound destinations.
    pub destinations: Vec<Destination>,
    /// Rules evaluated in declaration order.
    pub rules: Vec<Rule>,
    /// Optional event and rate limits.
    pub limits: Limits,
    /// Security posture applied while evaluating events.
    pub security: Security,
}
/// A named outbound destination and its host allow-list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    /// Stable destination identifier.
    pub id: String,
    /// Normalized transport protocol.
    pub protocol: Protocol,
    /// DNS hosts approved for this destination.
    pub allowed_hosts: Vec<String>,
}
/// Supported destination protocols.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// Sentry envelope transport.
    Sentry,
}
/// A policy rule and its validated action parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Stable rule identifier used in safe audit metadata.
    pub id: String,
    /// Selector used to determine whether the rule applies.
    pub matcher: Matcher,
    /// Transformation or terminal action to perform.
    pub action: RuleAction,
}

/// A validated action and the parameters that action requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleAction {
    /// Remove the matching field.
    Remove,
    /// Replace the matching value with a fixed marker.
    Replace {
        /// Fixed value written in place of the match.
        marker: String,
    },
    /// Preserve a nonzero number of leading characters and mask the rest.
    Mask {
        /// Number of leading characters to keep visible.
        preserve: NonZeroU64,
    },
    /// Produce a stable pseudonym using a local key reference.
    HmacSha256 {
        /// Identifier of the locally configured HMAC key.
        key_ref: String,
    },
    /// Reject the complete event.
    DropEvent,
    /// Do not forward the event and record a safe audit outcome.
    Quarantine,
    /// Send the sanitized event to an approved destination.
    Route {
        /// Identifier of the approved destination.
        destination: String,
    },
}

impl RuleAction {
    /// Returns the kind of action represented by this validated rule action.
    pub fn kind(&self) -> Action {
        match self {
            Self::Remove => Action::Remove,
            Self::Replace { .. } => Action::Replace,
            Self::Mask { .. } => Action::Mask,
            Self::HmacSha256 { .. } => Action::HmacSha256,
            Self::DropEvent => Action::DropEvent,
            Self::Quarantine => Action::Quarantine,
            Self::Route { .. } => Action::Route,
        }
    }
}
/// A rule selector based on fields or sensitive-value detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Matcher {
    /// Match JSON paths or object keys.
    Match(Match),
    /// Match configured sensitive-value types.
    Detect(Vec<String>),
}
/// Field and key selectors for a matching rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    /// Optional compiled JSONPath expression.
    pub json_path: Option<JsonPath>,
    /// Compiled JSONPath expressions to inspect.
    pub paths: Vec<JsonPath>,
    /// Object key names to inspect.
    pub key_matches: Vec<String>,
}
/// Actions supported by the policy contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Remove the matching field.
    Remove,
    /// Replace the matching value with a fixed marker.
    Replace,
    /// Preserve a configured portion of the matching value.
    Mask,
    /// Produce a stable pseudonym using a local key reference.
    HmacSha256,
    /// Reject the complete event.
    DropEvent,
    /// Do not forward the event and record a safe audit outcome.
    Quarantine,
    /// Send the sanitized event to another approved destination.
    Route,
}

impl Display for Action {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Remove => "remove",
            Self::Replace => "replace",
            Self::Mask => "mask",
            Self::HmacSha256 => "hmac_sha256",
            Self::DropEvent => "drop_event",
            Self::Quarantine => "quarantine",
            Self::Route => "route",
        })
    }
}
/// Optional event and throughput limits.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Limits {
    /// Maximum event size in bytes.
    pub max_event_size: Option<u64>,
    /// Maximum string field length.
    pub max_string_field_length: Option<u64>,
    /// Maximum events per minute per project.
    pub events_per_minute_per_project: Option<u64>,
}
/// Security controls applied to incoming events.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Security {
    /// Whether unknown projects are rejected.
    pub reject_unknown_projects: bool,
    /// Whether attachments are rejected.
    pub reject_attachments: bool,
}
