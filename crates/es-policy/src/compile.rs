//! Policy compilation orchestration.

use crate::{
    destination::DestinationCatalog,
    error::PolicyError,
    model::{Policy, Security},
    rule::RuleCatalog,
    source::{RawLimits, RawPolicy, RawSecurity},
};
use sha2::{Digest, Sha256};
use validator::Validate;

/// Parses and validates a complete policy. The input is never retained in errors.
pub fn compile_yaml(source: &str) -> Result<Policy, PolicyError> {
    let raw: RawPolicy = yaml_serde::from_str(source).map_err(|_| PolicyError::Malformed)?;
    raw.validate()
        .map_err(|_| PolicyError::Malformed)?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(source.as_bytes())));
    PolicyCompiler::compile(raw, digest)
}

struct PolicyCompiler;

impl PolicyCompiler {
    fn compile(raw: RawPolicy, digest: String) -> Result<Policy, PolicyError> {
        Self::validate_version(raw.version)?;
        let destinations = DestinationCatalog::compile(raw.destinations)?;
        let rules = RuleCatalog::compile(raw.rules, &destinations)?;
        let limits = raw
            .limits
            .map(RawLimits::compile)
            .transpose()?
            .unwrap_or_default();
        Ok(Policy {
            version: raw.version,
            digest,
            destinations: destinations.into_values(),
            rules: rules.into_values(),
            limits,
            security: raw.security.unwrap_or_default().into(),
        })
    }

    fn validate_version(version: u64) -> Result<(), PolicyError> {
        if version == 1 {
            return Ok(());
        }
        Err(PolicyError::InvalidVersion)
    }
}

impl From<RawSecurity> for Security {
    fn from(value: RawSecurity) -> Self {
        Self {
            reject_unknown_projects: value.reject_unknown_projects,
            reject_attachments: value.reject_attachments,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::error::{RuleCause, RuleError, RuleField};
    use crate::model::Action;

    use sha2::{Digest, Sha256};

    use super::compile_yaml;

    const VALID_POLICY: &str = "version: 1\ndestinations:\n  - id: primary\n    protocol: sentry\n    allowed_hosts: [events.example.com]\nrules: []\n";

    #[test]
    fn compilation_identifies_the_exact_source_revision() {
        let policy = compile_yaml(VALID_POLICY).expect("valid policy");
        let reformatted = compile_yaml(&VALID_POLICY.replace("version: 1", "version: 1 "))
            .expect("valid reformatted policy");

        assert_eq!(policy.version, 1);
        assert_eq!(
            policy.digest,
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(VALID_POLICY.as_bytes()))
            )
        );
        assert_ne!(policy.digest, reformatted.digest);
    }

    #[test]
    fn malformed_yaml_is_rejected_without_returning_source() {
        let error = compile_yaml("version: [").expect_err("malformed YAML");

        assert_eq!(error.to_string(), "policy document is malformed");
        assert!(!error.to_string().contains("version: ["));
    }

    #[test]
    fn invalid_rule_parameters_are_rejected() {
        let source = VALID_POLICY.replace(
            "rules: []",
            "rules:\n  - id: bad-mask\n    match:\n      json_path: $.user.id\n    action: mask\n    preserve: 0",
        );

        let error = compile_yaml(&source).expect_err("zero preserve count");
        assert_eq!(
            error,
            crate::error::PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Preserve,
                cause: RuleCause::MustBePositive,
            })
        );
    }

    #[test]
    fn action_parameters_must_match_the_selected_action() {
        for (rule, expected_field, expected_cause) in [
            (
                "action: replace",
                RuleField::Marker,
                RuleCause::RequiredForAction(Action::Replace),
            ),
            (
                "action: remove\n    marker: redacted",
                RuleField::Marker,
                RuleCause::ForbiddenForAction(Action::Remove),
            ),
            (
                "action: hmac_sha256",
                RuleField::KeyRef,
                RuleCause::RequiredForAction(Action::HmacSha256),
            ),
            (
                "action: route",
                RuleField::Destination,
                RuleCause::RequiredForAction(Action::Route),
            ),
        ] {
            let source = VALID_POLICY.replace(
                "rules: []",
                &format!(
                    "rules:\n  - id: parameter-check\n    match:\n      json_path: $.user.id\n    {rule}"
                ),
            );
            let error = compile_yaml(&source).expect_err("invalid action parameters");
            assert_eq!(
                error,
                crate::error::PolicyError::Rule(RuleError::Invalid {
                    field: expected_field,
                    cause: expected_cause,
                })
            );
        }
    }

    #[test]
    fn destination_allow_list_rejects_hostname_confusion_attempts() {
        let policy = compile_yaml(VALID_POLICY).expect("valid policy");
        let destination = &policy.destinations[0];

        assert!(destination.allows_host("EVENTS.EXAMPLE.COM"));
        for host in [
            "events.example.com.attacker.test",
            "attacker-events.example.com",
            "events.example.com.",
            "events.example.com@attacker.test",
            "events.example.com:443",
            "127.0.0.1",
        ] {
            assert!(
                !destination.allows_host(host),
                "unexpectedly allowed {host}"
            );
        }
    }
}
