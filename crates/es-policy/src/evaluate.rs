//! Deterministic policy evaluation over normalized JSON values.

use std::collections::{BTreeMap, BTreeSet};

use hmac::{Hmac, Mac};
use serde_json::Value;
use serde_json_path::JsonPath;
use sha2::Sha256;
use thiserror::Error;

use crate::model::{Match, Matcher, Policy, Rule, RuleAction};

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

/// Failures that prevent a policy evaluation from completing.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EvaluationError {
    /// A matching HMAC rule referred to key material absent from local configuration.
    #[error("local key material for a matching policy rule is unavailable")]
    MissingKey,
    /// The HMAC implementation rejected key material.
    #[error("local key material for a matching policy rule is invalid")]
    InvalidKey,
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
        let mut result = Evaluation {
            data: data.clone(),
            applied_rule_ids: Vec::new(),
            status: EvaluationStatus::Forward,
            destination: None,
        };

        for rule in &self.rules {
            let Some(locations) = rule.matching_locations(&result.data, detected_values) else {
                continue;
            };

            rule.apply(&mut result, locations, local_keys)?;
            result
                .applied_rule_ids
                .push(rule.id.clone());
            if matches!(
                result.status,
                EvaluationStatus::Dropped | EvaluationStatus::Quarantined
            ) {
                break;
            }
        }

        Ok(result)
    }
}

impl Rule {
    fn matching_locations(
        &self,
        data: &Value,
        detected_values: &BTreeMap<String, Vec<String>>,
    ) -> Option<Vec<String>> {
        match &self.matcher {
            Matcher::Match(matcher) => {
                let locations = matcher.locations(data);
                (!locations.is_empty()).then_some(locations)
            }
            Matcher::Detect(types) => {
                let matched_types = types
                    .iter()
                    .filter_map(|kind| detected_values.get(kind))
                    .collect::<Vec<_>>();
                if matched_types.is_empty() {
                    return None;
                }
                let locations = matched_types
                    .into_iter()
                    .flatten()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                Some(locations)
            }
        }
    }

    fn apply(
        &self,
        result: &mut Evaluation,
        locations: Vec<String>,
        local_keys: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), EvaluationError> {
        match &self.action {
            RuleAction::DropEvent => {
                result.status = EvaluationStatus::Dropped;
                return Ok(());
            }
            RuleAction::Quarantine => {
                result.status = EvaluationStatus::Quarantined;
                return Ok(());
            }
            RuleAction::Route { destination } => {
                result.destination = Some(destination.clone());
                return Ok(());
            }
            _ => {}
        }

        let mut locations = locations;
        locations.sort_by(compare_removal_order);
        for pointer in locations {
            self.action
                .apply_at(&mut result.data, &pointer, local_keys)?;
        }
        Ok(())
    }
}

impl RuleAction {
    fn apply_at(
        &self,
        data: &mut Value,
        pointer: &str,
        local_keys: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), EvaluationError> {
        match self {
            Self::Remove => remove_at(data, pointer),
            Self::Replace { marker } => {
                if let Some(value) = data.pointer_mut(pointer) {
                    *value = Value::String(marker.clone());
                }
            }
            Self::Mask { preserve } => {
                if let Some(value) = data.pointer_mut(pointer)
                    && let Some(text) = value.as_str()
                {
                    let keep = preserve.get().min(usize::MAX as u64) as usize;
                    *value = Value::String(mask(text, keep));
                }
            }
            Self::HmacSha256 { key_ref } => {
                let key = local_keys
                    .get(key_ref)
                    .ok_or(EvaluationError::MissingKey)?;
                if let Some(value) = data.pointer_mut(pointer) {
                    let input = match value {
                        Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    let mut mac = Hmac::<Sha256>::new_from_slice(key)
                        .map_err(|_| EvaluationError::InvalidKey)?;
                    mac.update(input.as_bytes());
                    *value = Value::String(format!(
                        "hmac-sha256:{}",
                        hex::encode(mac.finalize().into_bytes())
                    ));
                }
            }
            Self::DropEvent | Self::Quarantine | Self::Route { .. } => {}
        }
        Ok(())
    }
}

impl Match {
    fn locations(&self, data: &Value) -> Vec<String> {
        let mut locations = BTreeSet::new();
        if let Some(path) = &self.json_path {
            add_jsonpath_locations(path, data, &mut locations);
        }
        for path in &self.paths {
            add_jsonpath_locations(path, data, &mut locations);
        }
        if !self.key_matches.is_empty() {
            let keys = self
                .key_matches
                .iter()
                .collect::<BTreeSet<_>>();
            collect_key_locations(data, "", &keys, &mut locations);
        }
        locations.into_iter().collect()
    }
}

fn add_jsonpath_locations(path: &JsonPath, data: &Value, locations: &mut BTreeSet<String>) {
    locations.extend(
        path.query_located(data)
            .locations()
            .map(|location| location.to_json_pointer()),
    );
}

fn collect_key_locations(
    value: &Value,
    pointer: &str,
    keys: &BTreeSet<&String>,
    locations: &mut BTreeSet<String>,
) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let child_pointer = format!("{pointer}/{}", escape_pointer_token(key));
                if keys.contains(key) {
                    locations.insert(child_pointer.clone());
                }
                collect_key_locations(child, &child_pointer, keys, locations);
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                collect_key_locations(child, &format!("{pointer}/{index}"), keys, locations);
            }
        }
        _ => {}
    }
}

fn escape_pointer_token(token: &str) -> String {
    token
        .replace('~', "~0")
        .replace('/', "~1")
}

fn pointer_depth(pointer: &str) -> usize {
    pointer
        .bytes()
        .filter(|byte| *byte == b'/')
        .count()
}

fn compare_removal_order(left: &str, right: &str) -> std::cmp::Ordering {
    pointer_depth(right)
        .cmp(&pointer_depth(left))
        .then_with(|| {
            let (left_parent, left_token) = left
                .rsplit_once('/')
                .unwrap_or(("", left));
            let (right_parent, right_token) = right
                .rsplit_once('/')
                .unwrap_or(("", right));
            if left_parent == right_parent {
                if let (Ok(left_index), Ok(right_index)) =
                    (left_token.parse::<usize>(), right_token.parse::<usize>())
                {
                    return right_index.cmp(&left_index);
                }
            }
            right.cmp(left)
        })
}

fn remove_at(data: &mut Value, pointer: &str) {
    if pointer.is_empty() {
        *data = Value::Null;
        return;
    }
    let Some((parent_pointer, token)) = pointer.rsplit_once('/') else {
        return;
    };
    let parent_pointer = if parent_pointer.is_empty() {
        ""
    } else {
        parent_pointer
    };
    match data.pointer_mut(parent_pointer) {
        Some(Value::Object(object)) => {
            object.remove(&unescape_pointer_token(token));
        }
        Some(Value::Array(array)) => {
            if let Ok(index) = token.parse::<usize>()
                && index < array.len()
            {
                array.remove(index);
            }
        }
        _ => {}
    }
}

fn unescape_pointer_token(token: &str) -> String {
    token
        .replace("~1", "/")
        .replace("~0", "~")
}

fn mask(value: &str, preserved_characters: usize) -> String {
    let mut characters = value.chars();
    let preserved = characters
        .by_ref()
        .take(preserved_characters)
        .collect::<String>();
    format!("{preserved}{}", "*".repeat(characters.count()))
}
