//! Policy-related domain value objects.

use std::num::NonZeroU64;

use crate::error::CoreError;

/// A validated, positive version number of a policy.
///
/// `PolicyVersion` cannot contain zero, which makes it suitable for versioning
/// policies where numbering starts at one.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Hash, Eq, Ord)]
pub struct PolicyVersion(NonZeroU64);

impl PolicyVersion {
    /// Creates a policy version from a positive integer.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::PolicyVersionNotPositive`] when `value` is zero.
    pub fn new(value: u64) -> Result<Self, CoreError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(CoreError::PolicyVersionNotPositive)
    }

    /// Returns the policy version as an unsigned integer.
    pub fn as_u64(&self) -> u64 {
        self.0.get()
    }
}

/// A validated digest of the exact policy content used for an audit decision.
///
/// A digest records the policy content that was active, independently of its
/// [`PolicyVersion`]. This type stores a digest supplied by another layer; it
/// does not calculate hashes or choose a hashing algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyDigest(String);

impl PolicyDigest {
    /// Creates a policy digest from a non-empty value.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::EmptyPolicyDigest`] when `value` is empty.
    pub fn new(value: String) -> Result<Self, CoreError> {
        if value.is_empty() {
            return Err(CoreError::EmptyPolicyDigest);
        }

        Ok(Self(value))
    }

    /// Returns the policy digest as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated identifier of a policy rule applied to a payload.
///
/// A rule ID is safe audit metadata: it identifies the rule that acted without
/// retaining the rule definition or any matched payload value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuleId(String);

impl RuleId {
    /// Creates a rule identifier from a non-empty string.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::EmptyRuleId`] when `value` is empty.
    pub fn new(value: String) -> Result<Self, CoreError> {
        if value.is_empty() {
            return Err(CoreError::EmptyRuleId);
        }

        Ok(Self(value))
    }

    /// Returns the rule identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The version and exact-content digest that identify a policy revision.
///
/// A revision combines the human-readable policy version with the digest of
/// the exact policy content that was active for a decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRevision {
    version: PolicyVersion,
    digest: PolicyDigest,
}

impl PolicyRevision {
    /// Combines validated policy version and digest values into a revision.
    pub fn new(version: PolicyVersion, digest: PolicyDigest) -> Self {
        Self { version, digest }
    }

    /// Returns the policy version of this revision.
    pub fn version(&self) -> PolicyVersion {
        self.version
    }

    /// Returns the exact-content digest of this revision.
    pub fn digest(&self) -> &PolicyDigest {
        &self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::{PolicyDigest, PolicyRevision, PolicyVersion, RuleId};
    use crate::error::CoreError;

    #[test]
    fn preserves_a_positive_policy_version() {
        let policy_version = PolicyVersion::new(1);

        assert_eq!(policy_version.as_ref().map(PolicyVersion::as_u64), Ok(1));
    }

    #[test]
    fn rejects_zero_as_a_policy_version() {
        assert_eq!(
            PolicyVersion::new(0),
            Err(CoreError::PolicyVersionNotPositive)
        );
    }

    #[test]
    fn preserves_a_valid_policy_digest() {
        let policy_digest = PolicyDigest::new(
            "sha256:3a7bd3e2360a3d80e6f96f51c2a5f97884a7d6f5c7d2e9f0a1b2c3d4e5f60718".to_owned(),
        );

        assert_eq!(
            policy_digest.as_ref().map(PolicyDigest::as_str),
            Ok("sha256:3a7bd3e2360a3d80e6f96f51c2a5f97884a7d6f5c7d2e9f0a1b2c3d4e5f60718")
        );
    }

    #[test]
    fn rejects_an_empty_policy_digest() {
        assert_eq!(
            PolicyDigest::new(String::new()),
            Err(CoreError::EmptyPolicyDigest)
        );
    }

    #[test]
    fn accepts_a_valid_rule_id() {
        let rule_id = RuleId::new("remove-sensitive-headers".to_owned());

        assert_eq!(
            rule_id.as_ref().map(RuleId::as_str),
            Ok("remove-sensitive-headers")
        );
    }

    #[test]
    fn rejects_an_empty_rule_id() {
        assert_eq!(RuleId::new(String::new()), Err(CoreError::EmptyRuleId));
    }

    #[test]
    fn preserves_both_policy_revision_components() {
        let policy_revision = PolicyVersion::new(3).and_then(|version| {
            PolicyDigest::new("sha256:abc123".to_owned())
                .map(|digest| PolicyRevision::new(version, digest))
        });

        assert_eq!(
            policy_revision
                .as_ref()
                .map(PolicyRevision::version)
                .map(|version| version.as_u64()),
            Ok(3)
        );
        assert_eq!(
            policy_revision
                .as_ref()
                .map(|revision| revision.digest().as_str()),
            Ok("sha256:abc123")
        );
    }
}
