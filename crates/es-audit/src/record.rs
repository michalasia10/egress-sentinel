//! Validated metadata and SQLite row representation for an audit decision.

use es_core::{
    decision::{Decision, Outcome},
    detection::DetectionCategory,
    protocol::SourceProtocol,
};
use thiserror::Error;

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_DIGEST_BYTES: usize = 256;
const MAX_RULES: usize = 256;

/// Errors returned while validating or storing audit metadata.
#[derive(Debug, Error)]
pub enum AuditError {
    /// A field exceeded the audit model's storage bound.
    #[error("audit field {field} exceeds its {maximum}-byte limit")]
    FieldTooLong {
        /// Name of the metadata field that exceeded its limit.
        field: &'static str,
        /// Maximum permitted UTF-8 byte length.
        maximum: usize,
    },
    /// Too many rule identifiers were supplied for one decision.
    #[error("decision has more than {MAX_RULES} applied rules")]
    TooManyRules,
    /// The payload size cannot be represented by SQLite's signed integer type.
    #[error("payload size exceeds SQLite's integer range")]
    PayloadSizeOutOfRange,
    /// An unsigned metadata value cannot be represented by SQLite's integer type.
    #[error("audit field {field} exceeds SQLite's integer range")]
    IntegerOutOfRange {
        /// Name of the metadata field that could not fit SQLite's integer type.
        field: &'static str,
    },
    /// A metadata list could not be serialized as JSON.
    #[error("could not encode audit metadata list")]
    Json(#[from] serde_json::Error),
    /// SQLx could not open, initialize, or write the audit store.
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    /// SQLx could not apply an audit schema migration.
    #[error(transparent)]
    Migration(#[from] sqlx::migrate::MigrateError),
}

/// A persisted row decoded from the audit table.
#[derive(Debug, PartialEq, sqlx::FromRow)]
pub struct DecisionAuditRecord {
    /// SQLite-generated row identifier.
    pub id: i64,
    /// Decision timestamp in Unix milliseconds.
    pub timestamp_unix_ms: i64,
    /// Project identifier stored for the decision.
    pub project_id: String,
    /// Source protocol label stored for the decision.
    pub source_protocol: String,
    /// Destination identifier stored for the decision.
    pub destination_id: String,
    /// Outcome label stored for the decision.
    pub outcome: String,
    /// Policy version stored for the decision.
    pub policy_version: i64,
    /// Policy digest stored for the decision.
    pub policy_digest: String,
    /// JSON-encoded applied rule identifiers.
    pub applied_rule_ids: String,
    /// JSON-encoded detection category labels.
    pub detection_categories: String,
    /// Payload size in bytes.
    pub payload_size_bytes: i64,
    /// SQLite value of the raw payload storage flag.
    pub raw_payload_stored: i64,
}

/// Owns bounded, payload-free values prepared for insertion.
pub(crate) struct DecisionAuditDraft {
    pub(crate) timestamp_unix_ms: i64,
    pub(crate) project_id: String,
    pub(crate) source_protocol: SourceProtocol,
    pub(crate) destination_id: String,
    pub(crate) outcome: Outcome,
    pub(crate) policy_version: i64,
    pub(crate) policy_digest: String,
    pub(crate) applied_rule_ids: Vec<String>,
    pub(crate) detection_categories: Vec<DetectionCategory>,
    pub(crate) payload_size_bytes: i64,
}

impl DecisionAuditDraft {
    pub(crate) fn new(timestamp_unix_ms: i64, decision: &Decision) -> Result<Self, AuditError> {
        let draft = Self {
            timestamp_unix_ms,
            project_id: decision
                .project_id()
                .as_str()
                .to_owned(),
            source_protocol: decision.source_protocol(),
            destination_id: decision
                .destination_id()
                .as_str()
                .to_owned(),
            outcome: decision.outcome(),
            policy_version: i64::try_from(
                decision
                    .policy_revision()
                    .version()
                    .as_u64(),
            )
            .map_err(|_| AuditError::IntegerOutOfRange {
                field: "policy_version",
            })?,
            policy_digest: decision
                .policy_revision()
                .digest()
                .as_str()
                .to_owned(),
            applied_rule_ids: decision
                .applied_rules()
                .iter()
                .map(|rule| rule.rule_id().as_str().to_owned())
                .collect(),
            detection_categories: decision
                .detection_categories()
                .iter()
                .copied()
                .collect(),
            payload_size_bytes: i64::try_from(decision.payload_size().as_u64())
                .map_err(|_| AuditError::PayloadSizeOutOfRange)?,
        };
        for (field, value, maximum) in [
            (
                "project_id",
                draft.project_id.as_str(),
                MAX_IDENTIFIER_BYTES,
            ),
            (
                "destination_id",
                draft.destination_id.as_str(),
                MAX_IDENTIFIER_BYTES,
            ),
            (
                "policy_digest",
                draft.policy_digest.as_str(),
                MAX_DIGEST_BYTES,
            ),
        ] {
            if value.len() > maximum {
                return Err(AuditError::FieldTooLong { field, maximum });
            }
        }
        if draft.applied_rule_ids.len() > MAX_RULES {
            return Err(AuditError::TooManyRules);
        }
        for rule_id in &draft.applied_rule_ids {
            if rule_id.len() > MAX_IDENTIFIER_BYTES {
                return Err(AuditError::FieldTooLong {
                    field: "rule_id",
                    maximum: MAX_IDENTIFIER_BYTES,
                });
            }
        }
        Ok(draft)
    }
}
