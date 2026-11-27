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

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

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
        MIGRATOR.run(&pool).await?;

        Ok(Self { pool })
    }

    /// Records a decision's safe metadata using bound SQL parameters.
    pub async fn record_decision(
        &self,
        timestamp_unix_ms: i64,
        decision: &Decision,
    ) -> Result<(), AuditError> {
        DecisionAuditRecord::from_decision(timestamp_unix_ms, decision)?
            .insert(&self.pool)
            .await
    }
}

/// Owns the bounded, payload-free representation written to SQLite.
struct DecisionAuditRecord {
    timestamp_unix_ms: i64,
    project_id: String,
    source_protocol: SourceProtocol,
    destination_id: String,
    outcome: Outcome,
    policy_version: i64,
    policy_digest: String,
    applied_rule_ids: Vec<String>,
    detection_categories: Vec<DetectionCategory>,
    payload_size_bytes: i64,
}

impl DecisionAuditRecord {
    fn from_decision(timestamp_unix_ms: i64, decision: &Decision) -> Result<Self, AuditError> {
        let record = Self {
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
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), AuditError> {
        for (field, value, maximum) in [
            ("project_id", self.project_id.as_str(), MAX_IDENTIFIER_BYTES),
            (
                "destination_id",
                self.destination_id.as_str(),
                MAX_IDENTIFIER_BYTES,
            ),
            (
                "policy_digest",
                self.policy_digest.as_str(),
                MAX_DIGEST_BYTES,
            ),
        ] {
            if value.len() > maximum {
                return Err(AuditError::FieldTooLong { field, maximum });
            }
        }
        if self.applied_rule_ids.len() > MAX_RULES {
            return Err(AuditError::TooManyRules);
        }
        for rule_id in &self.applied_rule_ids {
            if rule_id.len() > MAX_IDENTIFIER_BYTES {
                return Err(AuditError::FieldTooLong {
                    field: "rule_id",
                    maximum: MAX_IDENTIFIER_BYTES,
                });
            }
        }
        Ok(())
    }

    async fn insert(&self, pool: &SqlitePool) -> Result<(), AuditError> {
        let applied_rule_ids = serde_json::to_string(&self.applied_rule_ids)?;
        let detection_categories = serde_json::to_string(
            &self
                .detection_categories
                .iter()
                .map(|category| match category {
                    DetectionCategory::Jwt => "jwt",
                    DetectionCategory::ApiKey => "api_key",
                    DetectionCategory::PrivateKey => "private_key",
                    DetectionCategory::ConnectionString => "connection_string",
                })
                .collect::<Vec<_>>(),
        )?;

        sqlx::query(
            "INSERT INTO decision_audit (
                 timestamp_unix_ms, project_id, source_protocol, destination_id,
                 outcome, policy_version, policy_digest, applied_rule_ids,
                 detection_categories, payload_size_bytes, raw_payload_stored
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        )
        .bind(self.timestamp_unix_ms)
        .bind(&self.project_id)
        .bind(match self.source_protocol {
            SourceProtocol::SentryEnvelope => "sentry_envelope",
        })
        .bind(&self.destination_id)
        .bind(match self.outcome {
            Outcome::Forwarded => "forwarded",
            Outcome::Dropped => "dropped",
            Outcome::Quarantined => "quarantined",
            Outcome::Rejected => "rejected",
            Outcome::Failed => "failed",
        })
        .bind(self.policy_version)
        .bind(&self.policy_digest)
        .bind(applied_rule_ids)
        .bind(detection_categories)
        .bind(self.payload_size_bytes)
        .execute(pool)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::SqliteAuditStore;
    use es_core::{
        decision::{AppliedAction, AppliedRule, Decision, DecisionResolution, PayloadSizeBytes},
        detection::DetectionCategory,
        identifiers::{DestinationId, ProjectId},
        policy::{PolicyDigest, PolicyRevision, PolicyVersion, RuleId},
        protocol::SourceProtocol,
    };

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

        let stored_values: (
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
        ) = sqlx::query_as(
            "SELECT timestamp_unix_ms, project_id, source_protocol, destination_id, outcome,
                    policy_version, policy_digest, applied_rule_ids, detection_categories,
                    payload_size_bytes, raw_payload_stored FROM decision_audit",
        )
        .fetch_one(&store.pool)
        .await?;
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
