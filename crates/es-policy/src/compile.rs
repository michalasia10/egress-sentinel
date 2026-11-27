//! Policy compilation orchestration.

use crate::{
    destination::DestinationCatalog,
    error::PolicyError,
    model::{Policy, Security},
    rule::RuleCatalog,
    source::{RawLimits, RawPolicy, RawSecurity},
};
use validator::Validate;

/// Parses and validates a complete policy. The input is never retained in errors.
pub fn compile_yaml(source: &str) -> Result<Policy, PolicyError> {
    let raw: RawPolicy = yaml_serde::from_str(source).map_err(|_| PolicyError::Malformed)?;
    raw.validate()
        .map_err(|_| PolicyError::Malformed)?;
    PolicyCompiler::compile(raw)
}

struct PolicyCompiler;

impl PolicyCompiler {
    fn compile(raw: RawPolicy) -> Result<Policy, PolicyError> {
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
