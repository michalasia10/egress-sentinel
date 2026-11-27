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
);
