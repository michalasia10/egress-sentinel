//! SQLite persistence for safe decision metadata.

use std::path::Path;

use crate::record::{AuditError, DecisionAuditDraft, DecisionAuditRecord};
use es_core::{
    decision::{Decision, Outcome},
    detection::DetectionCategory,
    protocol::SourceProtocol,
};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

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
    ) -> Result<DecisionAuditRecord, AuditError> {
        let draft = DecisionAuditDraft::new(timestamp_unix_ms, decision)?;
        self.insert(&draft).await
    }

    async fn insert(&self, draft: &DecisionAuditDraft) -> Result<DecisionAuditRecord, AuditError> {
        let applied_rule_ids = serde_json::to_string(&draft.applied_rule_ids)?;
        let detection_categories = serde_json::to_string(
            &draft
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
        let source_protocol = match draft.source_protocol {
            SourceProtocol::SentryEnvelope => "sentry_envelope",
        };
        let outcome = match draft.outcome {
            Outcome::Forwarded => "forwarded",
            Outcome::Dropped => "dropped",
            Outcome::Quarantined => "quarantined",
            Outcome::Rejected => "rejected",
            Outcome::Failed => "failed",
        };

        Ok(sqlx::query_as::<_, DecisionAuditRecord>(
            "INSERT INTO decision_audit (
                 timestamp_unix_ms, project_id, source_protocol, destination_id,
                 outcome, policy_version, policy_digest, applied_rule_ids,
                 detection_categories, payload_size_bytes, raw_payload_stored
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
             RETURNING id, timestamp_unix_ms, project_id, source_protocol, destination_id,
                       outcome, policy_version, policy_digest, applied_rule_ids,
                       detection_categories, payload_size_bytes, raw_payload_stored",
        )
        .bind(draft.timestamp_unix_ms)
        .bind(&draft.project_id)
        .bind(source_protocol)
        .bind(&draft.destination_id)
        .bind(outcome)
        .bind(draft.policy_version)
        .bind(&draft.policy_digest)
        .bind(applied_rule_ids)
        .bind(detection_categories)
        .bind(draft.payload_size_bytes)
        .fetch_one(&self.pool)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{DecisionAuditRecord, SqliteAuditStore};
    use es_core::{
        decision::{
            AppliedAction, AppliedRule, Decision, DecisionInput, DecisionResolution,
            PayloadSizeBytes,
        },
        detection::DetectionCategory,
        identifiers::{DestinationId, ProjectId},
        policy::{PolicyDigest, PolicyRevision, PolicyVersion, RuleId},
        protocol::SourceProtocol,
    };

    fn sample_decision() -> Result<Decision, Box<dyn std::error::Error>> {
        Ok(Decision::from_input(DecisionInput {
            project_id: ProjectId::new("project-a".to_owned())?,
            destination_id: DestinationId::new("destination-a".to_owned())?,
            source_protocol: SourceProtocol::SentryEnvelope,
            payload_size: PayloadSizeBytes::new(42),
            policy_revision: PolicyRevision::new(
                PolicyVersion::new(7)?,
                PolicyDigest::new("sha256:abc123".to_owned())?,
            ),
            resolution: DecisionResolution::Forwarded,
            applied_rules: vec![AppliedRule::new(
                RuleId::new("remove-token".to_owned())?,
                AppliedAction::Remove,
            )],
            detection_categories: BTreeSet::from([
                DetectionCategory::Jwt,
                DetectionCategory::ApiKey,
            ]),
        })?)
    }

    #[tokio::test]
    async fn stores_required_metadata_without_payload_or_secret_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteAuditStore::in_memory().await?;
        let decision = sample_decision()?;
        let stored_values = store
            .record_decision(1_800_000_000_000, &decision)
            .await?;
        assert_eq!(
            stored_values,
            DecisionAuditRecord {
                id: 1,
                timestamp_unix_ms: 1_800_000_000_000,
                project_id: "project-a".to_owned(),
                source_protocol: "sentry_envelope".to_owned(),
                destination_id: "destination-a".to_owned(),
                outcome: "forwarded".to_owned(),
                policy_version: 7,
                policy_digest: "sha256:abc123".to_owned(),
                applied_rule_ids: "[\"remove-token\"]".to_owned(),
                detection_categories: "[\"jwt\",\"api_key\"]".to_owned(),
                payload_size_bytes: 42,
                raw_payload_stored: 0,
            }
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
