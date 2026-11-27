//! Deterministic policy evaluation.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{
    error::EvaluationError,
    event::{FieldPaths, NormalizedEvent},
    model::{Policy, Rule, RuleAction},
};

/// The terminal status produced by evaluating a policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationStatus {
    /// The sanitized event may continue to its selected destination.
    Forward,
    /// Policy rejected the complete event.
    Dropped,
    /// Policy stopped processing and selected a safe quarantine outcome.
    Quarantined,
}

/// The deterministic result of applying a compiled policy.
#[derive(Clone, Debug, PartialEq)]
pub struct Evaluation {
    /// The sanitized normalized event. Terminal actions retain the data for local handling.
    pub data: Value,
    /// IDs of rules that matched, in policy declaration order.
    pub applied_rule_ids: Vec<String>,
    /// Final evaluation status.
    pub status: EvaluationStatus,
    /// Destination selected by the last matching route action, if any.
    pub destination: Option<String>,
}

impl Policy {
    /// Evaluates this policy against normalized JSON data without performing I/O.
    ///
    /// `detected_values` maps normalized sensitive-value category names to JSON Pointers in the
    /// normalized event. `local_keys` supplies secret bytes by policy `key_ref`; key material is
    /// neither retained nor returned.
    pub fn evaluate(
        &self,
        data: &Value,
        detected_values: &BTreeMap<String, Vec<String>>,
        local_keys: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Evaluation, EvaluationError> {
        let mut applied_rule_ids = Vec::new();
        let mut status = EvaluationStatus::Forward;
        let mut destination = None;
        let mut event = NormalizedEvent::new(data.clone());

        for rule in &self.rules {
            let Some(fields) = event.matching_fields(&rule.matcher, detected_values) else {
                continue;
            };
            rule.apply(
                &mut status,
                &mut destination,
                &mut event,
                fields,
                local_keys,
            )?;
            applied_rule_ids.push(rule.id.clone());
            if matches!(
                status,
                EvaluationStatus::Dropped | EvaluationStatus::Quarantined
            ) {
                break;
            }
        }
        Ok(Evaluation {
            data: event.into_value(),
            applied_rule_ids,
            status,
            destination,
        })
    }
}

impl Rule {
    fn apply(
        &self,
        status: &mut EvaluationStatus,
        selected_destination: &mut Option<String>,
        event: &mut NormalizedEvent,
        fields: FieldPaths,
        local_keys: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), EvaluationError> {
        match &self.action {
            RuleAction::DropEvent => *status = EvaluationStatus::Dropped,
            RuleAction::Quarantine => *status = EvaluationStatus::Quarantined,
            RuleAction::Route { destination } => {
                *selected_destination = Some(destination.clone());
            }
            action => event.apply(action, fields, local_keys)?,
        }
        Ok(())
    }
}
