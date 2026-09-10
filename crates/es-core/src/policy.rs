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

#[cfg(test)]
mod tests {
    use super::PolicyVersion;
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
}
