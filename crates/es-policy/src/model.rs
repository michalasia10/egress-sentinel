//! Validated policy model.
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
    pub action: Action,
    /// Local deployment key identifier, never key material.
    pub key_ref: Option<String>,
    /// Fixed replacement marker, when the action is `replace`.
    pub marker: Option<String>,
    /// Number of value characters to preserve, when the action is `mask`.
    pub preserve: Option<u64>,
    /// Approved destination identifier, when the action is `route`.
    pub destination: Option<String>,
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
    /// Optional JSONPath expression.
    pub json_path: Option<String>,
    /// JSONPath expressions to inspect.
    pub paths: Vec<String>,
    /// Object key names to inspect.
    pub key_matches: Vec<String>,
}
/// Actions supported by the policy contract.
#[derive(Clone, Debug, PartialEq, Eq)]
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
