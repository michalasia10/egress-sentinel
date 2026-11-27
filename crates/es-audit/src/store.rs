//! SQLite persistence for safe decision metadata.

use std::path::Path;

use es_core::{
    decision::{Decision, Outcome},
    detection::DetectionCategory,
    protocol::SourceProtocol,
};
use rusqlite::{Connection, params};
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
    /// SQLite could not open, initialize, or write the audit store.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// SQLite-backed store for decision metadata only.
pub struct SqliteAuditStore {
    connection: Connection,
}

impl SqliteAuditStore {
    /// Opens or creates an audit database at `path` and initializes its schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        Self::from_connection(Connection::open(path)?)
    }

    /// Creates an in-memory audit database.
    pub fn in_memory() -> Result<Self, AuditError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self, AuditError> {
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS decision_audit (
                 id INTEGER PRIMARY KEY,
                 timestamp_unix_ms INTEGER NOT NULL,
                 project_id TEXT NOT NULL,
                 source_protocol TEXT NOT NULL,
                 destination_id TEXT NOT NULL,
                 outcome TEXT NOT NULL,
                 policy_version INTEGER NOT NULL,
                 policy_digest TEXT NOT NULL,
                 applied_rule_ids TEXT NOT NULL,
                 detection_categories TEXT NOT NULL,
                 payload_size_bytes INTEGER NOT NULL,
                 raw_payload_stored INTEGER NOT NULL DEFAULT 0 CHECK (raw_payload_stored = 0)
             );",
        )?;
        Ok(Self { connection })
    }

    /// Records a decision's safe metadata using bound SQL parameters.
    pub fn record_decision(
        &self,
        timestamp_unix_ms: i64,
        decision: &Decision,
    ) -> Result<(), AuditError> {
        let project_id = decision.project_id().as_str();
        let destination_id = decision.destination_id().as_str();
        let policy_digest = decision
            .policy_revision()
            .digest()
            .as_str();
        validate_length("project_id", project_id, MAX_IDENTIFIER_BYTES)?;
        validate_length("destination_id", destination_id, MAX_IDENTIFIER_BYTES)?;
        validate_length("policy_digest", policy_digest, MAX_DIGEST_BYTES)?;
        if decision.applied_rules().len() > MAX_RULES {
            return Err(AuditError::TooManyRules);
        }
        for rule in decision.applied_rules() {
            validate_length("rule_id", rule.rule_id().as_str(), MAX_IDENTIFIER_BYTES)?;
        }

        let payload_size = i64::try_from(decision.payload_size().as_u64())
            .map_err(|_| AuditError::PayloadSizeOutOfRange)?;
        let policy_version = i64::try_from(
            decision
                .policy_revision()
                .version()
                .as_u64(),
        )
        .map_err(|_| AuditError::IntegerOutOfRange {
            field: "policy_version",
        })?;
        let rule_ids = json_strings(
            decision
                .applied_rules()
                .iter()
                .map(|rule| rule.rule_id().as_str()),
        )?;
        let categories = json_strings(
            decision
                .detection_categories()
                .iter()
                .map(detection_category_label),
        )?;

        self.connection.execute(
            "INSERT INTO decision_audit (
                 timestamp_unix_ms, project_id, source_protocol, destination_id,
                 outcome, policy_version, policy_digest, applied_rule_ids,
                 detection_categories, payload_size_bytes, raw_payload_stored
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0)",
            params![
                timestamp_unix_ms,
                project_id,
                source_protocol_label(decision.source_protocol()),
                destination_id,
                outcome_label(decision.outcome()),
                policy_version,
                policy_digest,
                rule_ids,
                categories,
                payload_size,
            ],
        )?;
        Ok(())
    }
}

fn validate_length(field: &'static str, value: &str, maximum: usize) -> Result<(), AuditError> {
    if value.len() > maximum {
        return Err(AuditError::FieldTooLong { field, maximum });
    }
    Ok(())
}

fn json_strings<'a>(values: impl Iterator<Item = &'a str>) -> Result<String, AuditError> {
    Ok(serde_json::to_string(&values.collect::<Vec<_>>())?)
}

fn source_protocol_label(protocol: SourceProtocol) -> &'static str {
    match protocol {
        SourceProtocol::SentryEnvelope => "sentry_envelope",
    }
}

fn outcome_label(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Forwarded => "forwarded",
        Outcome::Dropped => "dropped",
        Outcome::Quarantined => "quarantined",
        Outcome::Rejected => "rejected",
        Outcome::Failed => "failed",
    }
}

fn detection_category_label(category: &DetectionCategory) -> &'static str {
    match category {
        DetectionCategory::Jwt => "jwt",
        DetectionCategory::ApiKey => "api_key",
        DetectionCategory::PrivateKey => "private_key",
        DetectionCategory::ConnectionString => "connection_string",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use es_core::{
        decision::{AppliedAction, AppliedRule, Decision, DecisionResolution, PayloadSizeBytes},
        detection::DetectionCategory,
        identifiers::{DestinationId, ProjectId},
        policy::{PolicyDigest, PolicyRevision, PolicyVersion, RuleId},
        protocol::SourceProtocol,
    };
    use rusqlite::params;

    use super::SqliteAuditStore;

    fn sample_decision() -> Result<Decision, Box<dyn std::error::Error>> {
        Ok(Decision::new(
            ProjectId::new("project-a".to_owned())?,
            DestinationId::new("destination-a".to_owned())?,
            SourceProtocol::SentryEnvelope,
            PayloadSizeBytes::new(42),
            PolicyRevision::new(
                PolicyVersion::new(7)?,
                PolicyDigest::new("sha256:abc123".to_owned())?,
            ),
            DecisionResolution::Forwarded,
            vec![AppliedRule::new(
                RuleId::new("remove-token".to_owned())?,
                AppliedAction::Remove,
            )],
            BTreeSet::from([DetectionCategory::Jwt, DetectionCategory::ApiKey]),
        )?)
    }

    #[test]
    fn stores_required_metadata_without_payload_or_secret_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteAuditStore::in_memory()?;
        let decision = sample_decision()?;
        store.record_decision(1_800_000_000_000, &decision)?;

        let row: (
            i64,
            String,
            String,
            String,
            String,
            i64,
            String,
            String,
            String,
            i64,
            i64,
        ) = store.connection.query_row(
            "SELECT timestamp_unix_ms, project_id, source_protocol, destination_id, outcome,
                        policy_version, policy_digest, applied_rule_ids, detection_categories,
                        payload_size_bytes, raw_payload_stored FROM decision_audit",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )?;
        assert_eq!(
            row,
            (
                1_800_000_000_000,
                "project-a".into(),
                "sentry_envelope".into(),
                "destination-a".into(),
                "forwarded".into(),
                7,
                "sha256:abc123".into(),
                "[\"remove-token\"]".into(),
                "[\"jwt\",\"api_key\"]".into(),
                42,
                0
            )
        );

        let stored_values = format!("{row:?}");
        assert!(!stored_values.contains("raw-payload-sentinel"));
        assert!(!stored_values.contains("secret-value-sentinel"));
        Ok(())
    }

    #[test]
    fn schema_rejects_raw_payload_storage() -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteAuditStore::in_memory()?;
        let rejected = store.connection.execute(
            "INSERT INTO decision_audit (timestamp_unix_ms, project_id, source_protocol,
             destination_id, outcome, policy_version, policy_digest, applied_rule_ids,
             detection_categories, payload_size_bytes, raw_payload_stored)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                0,
                "p",
                "sentry_envelope",
                "d",
                "forwarded",
                1,
                "d",
                "[]",
                "[]",
                0,
                1
            ],
        );
        assert!(rejected.is_err());
        Ok(())
    }
}
