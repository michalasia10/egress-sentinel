//! Private source representation of a YAML policy document.

use serde::Deserialize;

/// Unvalidated policy data read from YAML.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(super) struct RawPolicy {
    pub(super) version: u64,
}

#[cfg(test)]
mod tests {
    use super::RawPolicy;

    #[test]
    fn deserializes_a_minimal_policy_version() -> Result<(), yaml_serde::Error> {
        let policy: RawPolicy = yaml_serde::from_str("version: 1")?;

        assert_eq!(policy.version, 1);

        Ok(())
    }
}
