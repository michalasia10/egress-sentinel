//! Domain types that describe a policy decision.
use crate::{
    error::CoreError,
    identifiers::{DestinationId, ProjectId},
    policy::PolicyRevision,
};

/// The final outcome of handling a payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The payload was forwarded to its destination.
    Forwarded,
    /// The payload was intentionally discarded.
    Dropped,
    /// The payload was not forwarded externally and its decision was recorded safely.
    ///
    /// This outcome does not guarantee that the payload itself is retained locally.
    Quarantined,
    /// The payload was refused at ingress because of authentication, rate limits, or protocol or schema validation.
    Rejected,
    /// Processing the payload could not be completed.
    Failed,
}

/// A decision made after a project and its active policy revision were selected.
///
/// An ingress rejection cannot be represented as a `Decision`, because no
/// policy revision is selected for such a request.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Decision {
    project_id: ProjectId,
    destination_id: DestinationId,
    policy_revision: PolicyRevision,
    outcome: Outcome,
}

impl Decision {
    /// Creates a decision associated with a selected policy revision.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::RejectedOutcomeForPolicyDecision`] when `outcome`
    /// is [`Outcome::Rejected`].
    pub fn new(
        project_id: ProjectId,
        destination_id: DestinationId,
        policy_revision: PolicyRevision,
        outcome: Outcome,
    ) -> Result<Self, CoreError> {
        if outcome == Outcome::Rejected {
            return Err(CoreError::RejectedOutcomeForPolicyDecision);
        }

        Ok(Self {
            project_id,
            destination_id,
            policy_revision,
            outcome,
        })
    }

    /// Returns the project this decision belongs to.
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    /// Returns the destination selected for this decision.
    pub fn destination_id(&self) -> &DestinationId {
        &self.destination_id
    }

    /// Returns the policy revision used to make this decision.
    pub fn policy_revision(&self) -> &PolicyRevision {
        &self.policy_revision
    }

    /// Returns the outcome of this decision.
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }
}

#[cfg(test)]
mod tests {
    use super::{Decision, Outcome};
    use crate::{
        error::CoreError,
        identifiers::{DestinationId, ProjectId},
        policy::{PolicyDigest, PolicyRevision, PolicyVersion},
    };

    fn policy_revision() -> Result<PolicyRevision, CoreError> {
        let version = PolicyVersion::new(3)?;
        let digest = PolicyDigest::new("sha256:abc123".to_owned())?;

        Ok(PolicyRevision::new(version, digest))
    }

    #[test]
    fn creates_a_forwarded_decision() -> Result<(), CoreError> {
        let decision = Decision::new(
            ProjectId::new("project-a".to_owned())?,
            DestinationId::new("destination-a".to_owned())?,
            policy_revision()?,
            Outcome::Forwarded,
        )?;

        assert_eq!(decision.project_id().as_str(), "project-a");
        assert_eq!(decision.destination_id().as_str(), "destination-a");
        assert_eq!(decision.policy_revision().version().as_u64(), 3);
        assert_eq!(
            decision.policy_revision().digest().as_str(),
            "sha256:abc123"
        );
        assert_eq!(decision.outcome(), Outcome::Forwarded);

        Ok(())
    }

    #[test]
    fn rejects_rejected_outcome_for_a_policy_decision() -> Result<(), CoreError> {
        let decision = Decision::new(
            ProjectId::new("project-a".to_owned())?,
            DestinationId::new("destination-a".to_owned())?,
            policy_revision()?,
            Outcome::Rejected,
        );

        assert_eq!(decision, Err(CoreError::RejectedOutcomeForPolicyDecision));

        Ok(())
    }
}
