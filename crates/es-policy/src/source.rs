//! Private, deliberately strict source representation of a YAML policy.
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub(super) struct RawPolicy {
    pub(super) version: u64,
    #[validate(length(min = 1), nested)]
    pub(super) destinations: Vec<RawDestination>,
    #[serde(default)]
    #[validate(nested)]
    pub(super) rules: Vec<RawRule>,
    #[serde(default)]
    pub(super) limits: Option<RawLimits>,
    #[serde(default)]
    pub(super) security: Option<RawSecurity>,
}
#[derive(Debug, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub(super) struct RawDestination {
    #[validate(length(min = 1))]
    pub(super) id: String,
    pub(super) protocol: String,
    #[validate(length(min = 1))]
    pub(super) allowed_hosts: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRule {
    #[validate(length(min = 1))]
    pub(super) id: String,
    #[serde(rename = "match", default)]
    #[validate(nested)]
    pub(super) match_: Option<RawMatch>,
    #[serde(default)]
    #[validate(nested)]
    pub(super) detect: Option<RawDetect>,
    #[validate(length(min = 1))]
    pub(super) action: String,
    #[serde(default)]
    pub(super) key_ref: Option<String>,
    #[serde(default)]
    pub(super) marker: Option<String>,
    #[serde(default)]
    pub(super) preserve: Option<u64>,
    #[serde(default)]
    pub(super) destination: Option<String>,
}
#[derive(Debug, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub(super) struct RawMatch {
    #[serde(default)]
    pub(super) json_path: Option<String>,
    #[serde(default)]
    pub(super) paths: Vec<String>,
    #[serde(default)]
    pub(super) key_matches: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub(super) struct RawDetect {
    #[validate(length(min = 1))]
    pub(super) types: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawLimits {
    #[serde(default)]
    pub(super) max_event_size: Option<RawSize>,
    #[serde(default)]
    pub(super) max_string_field_length: Option<u64>,
    #[serde(default)]
    pub(super) events_per_minute_per_project: Option<u64>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum RawSize {
    Bytes(u64),
    Text(String),
}
#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct RawSecurity {
    #[serde(default)]
    pub(super) reject_unknown_projects: bool,
    #[serde(default)]
    pub(super) reject_attachments: bool,
}
