//! SQLite persistence for safe decision metadata.

use std::path::Path;

use es_core::{
    decision::{Decision, Outcome},
    detection::DetectionCategory,
    protocol::SourceProtocol,
};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
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
}

/// SQLx-backed SQLite store for decision metadata only.
pub struct SqliteAuditStore {
    pool: SqlitePool,
}

impl SqliteAuditStore {
    /// Opens or creates an audit database at `path` and initializes its schema.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        Self::connect(options, 5).await
    }

    /// Creates an in-memory audit database.
    pub async fn in_memory() -> Result<Self, AuditError> {
        let options = SqliteConnectOptions::new()
            .filename(":memory:")
            .shared_cache(true);
        Self::connect(options, 1).await
    }

    async fn connect(
        options: SqliteConnectOptions,
        maximum_connections: u32,
    ) -> Result<Self, AuditError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(maximum_connections)
            .connect_with(options)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS decision_audit (
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
             )",
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    /// Records a decision's safe metadata using bound SQL parameters.
    pub async fn record_decision(
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

        sqlx::query(
            "INSERT INTO decision_audit (
                 timestamp_unix_ms, project_id, source_protocol, destination_id,
                 outcome, policy_version, policy_digest, applied_rule_ids,
                 detection_categories, payload_size_bytes, raw_payload_stored
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        )
        .bind(timestamp_unix_ms)
        .bind(project_id)
        .bind(source_protocol_label(decision.source_protocol()))
        .bind(destination_id)
        .bind(outcome_label(decision.outcome()))
        .bind(policy_version)
        .bind(policy_digest)
        .bind(rule_ids)
        .bind(categories)
        .bind(payload_size)
        .execute(&self.pool)
        .await?;

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
    use sqlx::Row;

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

    #[tokio::test]
    async fn stores_required_metadata_without_payload_or_secret_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteAuditStore::in_memory().await?;
        let decision = sample_decision()?;
        store
            .record_decision(1_800_000_000_000, &decision)
            .await?;

        let row = sqlx::query(
            "SELECT timestamp_unix_ms, project_id, source_protocol, destination_id, outcome,
                    policy_version, policy_digest, applied_rule_ids, detection_categories,
                    payload_size_bytes, raw_payload_stored FROM decision_audit",
        )
        .fetch_one(&store.pool)
        .await?;
        let stored_values = (
            row.try_get::<i64, _>("timestamp_unix_ms")?,
            row.try_get::<String, _>("project_id")?,
            row.try_get::<String, _>("source_protocol")?,
            row.try_get::<String, _>("destination_id")?,
            row.try_get::<String, _>("outcome")?,
            row.try_get::<i64, _>("policy_version")?,
            row.try_get::<String, _>("policy_digest")?,
            row.try_get::<String, _>("applied_rule_ids")?,
            row.try_get::<String, _>("detection_categories")?,
            row.try_get::<i64, _>("payload_size_bytes")?,
            row.try_get::<i64, _>("raw_payload_stored")?,
        );
        assert_eq!(
            stored_values,
            (
                1_800_000_000_000,
                "project-a".to_owned(),
                "sentry_envelope".to_owned(),
                "destination-a".to_owned(),
                "forwarded".to_owned(),
                7,
                "sha256:abc123".to_owned(),
                "[\"remove-token\"]".to_owned(),
                "[\"jwt\",\"api_key\"]".to_owned(),
                42,
                0
            )
        );

        let stored_values = format!("{stored_values:?}");
        assert!(!stored_values.contains("raw-payload-sentinel"));
        assert!(!stored_values.contains("secret-value-sentinel"));
        Ok(())
    }

    #[tokio::test]
    async fn schema_rejects_raw_payload_storage() -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteAuditStore::in_memory().await?;
        let result = sqlx::query(
            "INSERT INTO decision_audit (timestamp_unix_ms, project_id, source_protocol,
             destination_id, outcome, policy_version, policy_digest, applied_rule_ids,
             detection_categories, payload_size_bytes, raw_payload_stored)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(0_i64)
        .bind("p")
        .bind("sentry_envelope")
        .bind("d")
        .bind("forwarded")
        .bind(1_i64)
        .bind("d")
        .bind("[]")
        .bind("[]")
        .bind(0_i64)
        .bind(1_i64)
        .execute(&store.pool)
        .await;

        assert!(result.is_err());
        Ok(())
    }
}
