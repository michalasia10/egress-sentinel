//! Private source representation of a YAML policy document.

use serde::Deserialize;

/// Unvalidated policy data read from YAML.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(super) struct RawPolicy {
    pub(super) version: u64,
    pub(super) destinations: Vec<RawDestination>,
}

/// Unvalidated destination data read from YAML.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(super) struct RawDestination {
    pub(super) id: String,
    pub(super) protocol: String,
    pub(super) allowed_hosts: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::RawPolicy;

    #[test]
    fn deserializes_a_policy_with_a_destination() -> Result<(), yaml_serde::Error> {
        let policy: RawPolicy = yaml_serde::from_str(
            r"
version: 1
destinations:
  - id: sentry-eu
    protocol: sentry
    allowed_hosts: [o123.ingest.eu.sentry.io]
",
        )?;

        assert_eq!(policy.version, 1);
        assert_eq!(policy.destinations.len(), 1);
        assert_eq!(policy.destinations[0].id, "sentry-eu");
        assert_eq!(policy.destinations[0].protocol, "sentry");
        assert_eq!(
            policy.destinations[0].allowed_hosts[0],
            "o123.ingest.eu.sentry.io"
        );

        Ok(())
    }
}
