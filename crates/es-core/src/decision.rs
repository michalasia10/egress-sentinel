//! Domain types that describe a policy decision.

use std::collections::BTreeSet;

use crate::{
    detection::DetectionCategory,
    error::CoreError,
    identifiers::{DestinationId, ProjectId},
    policy::{PolicyRevision, RuleId},
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

/// An action already applied by the policy engine.
///
/// This is a record of policy evaluation, not an instruction to execute an
/// action or a representation of the policy rule that selected it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AppliedAction {
    /// A matching field was removed.
    Remove,
    /// A matching value was replaced with a fixed marker.
    Replace,
    /// An explicitly configured portion of a value was preserved.
    Mask,
    /// A stable pseudonym was produced with HMAC-SHA-256.
    HmacSha256,
    /// The sanitized payload was routed to another approved destination.
    Route,
    /// The complete event was dropped, terminating policy evaluation.
    DropEvent,
    /// The payload was not forwarded, terminating policy evaluation with a safe audit outcome.
    Quarantine,
}

impl AppliedAction {
    /// Returns the audit outcome associated with this terminal action.
    ///
    /// Returns `None` for actions that do not terminate policy evaluation.
    pub fn terminal_outcome(self) -> Option<Outcome> {
        match self {
            Self::DropEvent => Some(Outcome::Dropped),
            Self::Quarantine => Some(Outcome::Quarantined),
            _ => None,
        }
    }
}

/// A policy rule and the action it applied to a payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedRule {
    rule_id: RuleId,
    action: AppliedAction,
}

impl AppliedRule {
    /// Records an action applied by a validated policy rule.
    pub fn new(rule_id: RuleId, action: AppliedAction) -> Self {
        Self { rule_id, action }
    }

    /// Returns the identifier of the rule that was applied.
    pub fn rule_id(&self) -> &RuleId {
        &self.rule_id
    }

    /// Returns the action that the rule applied.
    pub fn action(&self) -> AppliedAction {
        self.action
    }
}

/// The internal reason that policy decision processing ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DecisionResolution {
    /// Processing completed and the payload was forwarded.
    Forwarded,
    /// Processing could not be completed.
    Failed,
    /// A terminal policy action ended processing.
    TerminatedByPolicy,
}

impl DecisionResolution {
    /// Returns the audit outcome when this resolution determines it directly.
    ///
    /// [`DecisionResolution::TerminatedByPolicy`] returns `None` because its
    /// audit outcome depends on the last terminal [`AppliedRule`].
    pub fn direct_outcome(self) -> Option<Outcome> {
        match self {
            Self::Forwarded => Some(Outcome::Forwarded),
            Self::Failed => Some(Outcome::Failed),
            Self::TerminatedByPolicy => None,
        }
    }
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
    resolution: DecisionResolution,
    applied_rules: Vec<AppliedRule>,
    detection_categories: BTreeSet<DetectionCategory>,
}

impl Decision {
    /// Creates a decision associated with a selected policy revision.
    ///
    /// # Errors
    ///
    /// Returns an error when the applied-rule sequence is inconsistent with
    /// `resolution` or contains a non-final terminal action.
    pub fn new(
        project_id: ProjectId,
        destination_id: DestinationId,
        policy_revision: PolicyRevision,
        resolution: DecisionResolution,
        applied_rules: Vec<AppliedRule>,
        detection_categories: BTreeSet<DetectionCategory>,
    ) -> Result<Self, CoreError> {
        if applied_rules
            .iter()
            .take(applied_rules.len().saturating_sub(1))
            .any(|applied_rule| applied_rule.action().terminal_outcome().is_some())
        {
            return Err(CoreError::NonFinalTerminalAction);
        }

        let has_terminal_final_action = applied_rules
            .last()
            .is_some_and(|applied_rule| applied_rule.action().terminal_outcome().is_some());

        match resolution {
            DecisionResolution::TerminatedByPolicy if !has_terminal_final_action => {
                return Err(CoreError::TerminatedByPolicyWithoutTerminalAction);
            }
            DecisionResolution::Forwarded | DecisionResolution::Failed
                if has_terminal_final_action =>
            {
                return Err(CoreError::DirectResolutionWithTerminalAction);
            }
            _ => {}
        }

        Ok(Self {
            project_id,
            destination_id,
            policy_revision,
            resolution,
            applied_rules,
            detection_categories,
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

    /// Returns the internal resolution of this decision.
    pub fn resolution(&self) -> DecisionResolution {
        self.resolution
    }

    /// Returns the policy rules applied while making this decision.
    pub fn applied_rules(&self) -> &[AppliedRule] {
        &self.applied_rules
    }

    /// Returns the unique detection categories found while making this decision.
    pub fn detection_categories(&self) -> &BTreeSet<DetectionCategory> {
        &self.detection_categories
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{AppliedAction, AppliedRule, Decision, DecisionResolution, Outcome};
    use crate::{
        detection::DetectionCategory,
        error::CoreError,
        identifiers::{DestinationId, ProjectId},
        policy::{PolicyDigest, PolicyRevision, PolicyVersion, RuleId},
    };

    fn policy_revision() -> Result<PolicyRevision, CoreError> {
        let version = PolicyVersion::new(3)?;
        let digest = PolicyDigest::new("sha256:abc123".to_owned())?;

        Ok(PolicyRevision::new(version, digest))
    }

    #[test]
    fn preserves_an_applied_rule_pair() -> Result<(), CoreError> {
        let applied_rule = AppliedRule::new(
            RuleId::new("remove-sensitive-headers".to_owned())?,
            AppliedAction::Remove,
        );

        assert_eq!(applied_rule.rule_id().as_str(), "remove-sensitive-headers");
        assert_eq!(applied_rule.action(), AppliedAction::Remove);

        Ok(())
    }

    #[test]
    fn maps_drop_event_to_dropped_outcome() {
        assert_eq!(
            AppliedAction::DropEvent.terminal_outcome(),
            Some(Outcome::Dropped)
        );
    }

    #[test]
    fn maps_quarantine_to_quarantined_outcome() {
        assert_eq!(
            AppliedAction::Quarantine.terminal_outcome(),
            Some(Outcome::Quarantined)
        );
    }

    #[test]
    fn returns_no_terminal_outcome_for_mask() {
        assert_eq!(AppliedAction::Mask.terminal_outcome(), None);
    }

    #[test]
    fn maps_forwarded_resolution_to_forwarded_outcome() {
        assert_eq!(
            DecisionResolution::Forwarded.direct_outcome(),
            Some(Outcome::Forwarded)
        );
    }

    #[test]
    fn maps_failed_resolution_to_failed_outcome() {
        assert_eq!(
            DecisionResolution::Failed.direct_outcome(),
            Some(Outcome::Failed)
        );
    }

    #[test]
    fn returns_no_direct_outcome_for_policy_termination() {
        assert_eq!(
            DecisionResolution::TerminatedByPolicy.direct_outcome(),
            None
        );
    }

    #[test]
    fn creates_a_forwarded_decision() -> Result<(), CoreError> {
        let decision = Decision::new(
            ProjectId::new("project-a".to_owned())?,
            DestinationId::new("destination-a".to_owned())?,
            policy_revision()?,
            DecisionResolution::Forwarded,
            vec![
                AppliedRule::new(
                    RuleId::new("remove-sensitive-headers".to_owned())?,
                    AppliedAction::Remove,
                ),
                AppliedRule::new(
                    RuleId::new("mask-sensitive-fields".to_owned())?,
                    AppliedAction::Mask,
                ),
            ],
            BTreeSet::from([DetectionCategory::Jwt, DetectionCategory::ApiKey]),
        )?;

        assert_eq!(decision.project_id().as_str(), "project-a");
        assert_eq!(decision.destination_id().as_str(), "destination-a");
        assert_eq!(decision.policy_revision().version().as_u64(), 3);
        assert_eq!(
            decision.policy_revision().digest().as_str(),
            "sha256:abc123"
        );
        assert_eq!(decision.resolution(), DecisionResolution::Forwarded);
        assert_eq!(
            decision
                .applied_rules()
                .iter()
                .map(|applied_rule| applied_rule.rule_id().as_str())
                .collect::<Vec<_>>(),
            ["remove-sensitive-headers", "mask-sensitive-fields"]
        );
        assert_eq!(
            decision
                .applied_rules()
                .iter()
                .map(AppliedRule::action)
                .collect::<Vec<_>>(),
            [AppliedAction::Remove, AppliedAction::Mask]
        );
        assert!(
            decision
                .detection_categories()
                .contains(&DetectionCategory::Jwt)
        );
        assert!(
            decision
                .detection_categories()
                .contains(&DetectionCategory::ApiKey)
        );

        Ok(())
    }

    #[test]
    fn creates_a_policy_terminated_decision_with_a_final_drop_event() -> Result<(), CoreError> {
        let decision = Decision::new(
            ProjectId::new("project-a".to_owned())?,
            DestinationId::new("destination-a".to_owned())?,
            policy_revision()?,
            DecisionResolution::TerminatedByPolicy,
            vec![AppliedRule::new(
                RuleId::new("drop-sensitive-event".to_owned())?,
                AppliedAction::DropEvent,
            )],
            BTreeSet::new(),
        )?;

        assert_eq!(
            decision.resolution(),
            DecisionResolution::TerminatedByPolicy
        );

        Ok(())
    }

    #[test]
    fn rejects_policy_termination_with_a_non_terminal_final_action() -> Result<(), CoreError> {
        let decision = Decision::new(
            ProjectId::new("project-a".to_owned())?,
            DestinationId::new("destination-a".to_owned())?,
            policy_revision()?,
            DecisionResolution::TerminatedByPolicy,
            vec![AppliedRule::new(
                RuleId::new("remove-sensitive-headers".to_owned())?,
                AppliedAction::Remove,
            )],
            BTreeSet::new(),
        );

        assert_eq!(
            decision,
            Err(CoreError::TerminatedByPolicyWithoutTerminalAction)
        );

        Ok(())
    }

    #[test]
    fn rejects_forwarding_with_a_terminal_final_action() -> Result<(), CoreError> {
        let decision = Decision::new(
            ProjectId::new("project-a".to_owned())?,
            DestinationId::new("destination-a".to_owned())?,
            policy_revision()?,
            DecisionResolution::Forwarded,
            vec![AppliedRule::new(
                RuleId::new("drop-sensitive-event".to_owned())?,
                AppliedAction::DropEvent,
            )],
            BTreeSet::new(),
        );

        assert_eq!(decision, Err(CoreError::DirectResolutionWithTerminalAction));

        Ok(())
    }

    #[test]
    fn rejects_a_terminal_action_before_the_final_applied_rule() -> Result<(), CoreError> {
        let decision = Decision::new(
            ProjectId::new("project-a".to_owned())?,
            DestinationId::new("destination-a".to_owned())?,
            policy_revision()?,
            DecisionResolution::TerminatedByPolicy,
            vec![
                AppliedRule::new(
                    RuleId::new("drop-sensitive-event".to_owned())?,
                    AppliedAction::DropEvent,
                ),
                AppliedRule::new(
                    RuleId::new("remove-sensitive-headers".to_owned())?,
                    AppliedAction::Remove,
                ),
            ],
            BTreeSet::new(),
        );

        assert_eq!(decision, Err(CoreError::NonFinalTerminalAction));

        Ok(())
    }
}
