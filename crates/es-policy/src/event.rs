//! Selection and mutation of normalized policy data.

use std::collections::{BTreeMap, BTreeSet};

use hmac::{Hmac, Mac};
use serde_json::Value;
use serde_json_path::{JsonPath, PathElement};
use sha2::Sha256;

use crate::{
    error::EvaluationError,
    model::{Match, Matcher, RuleAction},
};

/// Owns normalized event data and the field selection and mutation rules for JSON values.
pub(super) struct NormalizedEvent(Value);

/// Matched fields in a stable order suitable for applying mutations.
pub(super) struct FieldPaths(Vec<FieldPath>);

/// A typed path into a normalized JSON value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FieldPath(Vec<FieldSegment>);

/// A JSON object key or array index along a field path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FieldSegment {
    Key(String),
    Index(usize),
}

impl NormalizedEvent {
    pub(super) fn new(value: Value) -> Self {
        Self(value)
    }

    pub(super) fn into_value(self) -> Value {
        self.0
    }

    pub(super) fn matching_fields(
        &self,
        matcher: &Matcher,
        detected_values: &BTreeMap<String, Vec<String>>,
    ) -> Option<FieldPaths> {
        let mut paths = BTreeSet::new();
        match matcher {
            Matcher::Match(matcher) => self.add_matches(matcher, &mut paths),
            Matcher::Detect(types) => {
                let matching_types = types
                    .iter()
                    .filter_map(|kind| detected_values.get(kind))
                    .collect::<Vec<_>>();
                if matching_types.is_empty() {
                    return None;
                }
                for pointer in matching_types.into_iter().flatten() {
                    if let Some(path) = FieldPath::from_pointer(&self.0, pointer) {
                        paths.insert(path);
                    }
                }
            }
        }

        if paths.is_empty() && matches!(matcher, Matcher::Match(_)) {
            return None;
        }
        Some(FieldPaths::new(paths))
    }

    pub(super) fn apply(
        &mut self,
        action: &RuleAction,
        paths: FieldPaths,
        local_keys: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), EvaluationError> {
        for path in paths.0 {
            action.apply_to(self, &path, local_keys)?;
        }
        Ok(())
    }

    fn add_matches(&self, matcher: &Match, paths: &mut BTreeSet<FieldPath>) {
        if let Some(path) = &matcher.json_path {
            Self::add_jsonpath_matches(path, &self.0, paths);
        }
        for path in &matcher.paths {
            Self::add_jsonpath_matches(path, &self.0, paths);
        }
        if !matcher.key_matches.is_empty() {
            let keys = matcher
                .key_matches
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let mut path = FieldPath(Vec::new());
            Self::add_key_matches(&self.0, &keys, &mut path, paths);
        }
    }

    fn add_jsonpath_matches(expression: &JsonPath, value: &Value, paths: &mut BTreeSet<FieldPath>) {
        paths.extend(
            expression
                .query_located(value)
                .locations()
                .map(|location| {
                    FieldPath(
                        location
                            .iter()
                            .map(|element| match element {
                                PathElement::Name(name) => FieldSegment::Key((*name).to_owned()),
                                PathElement::Index(index) => FieldSegment::Index(*index),
                            })
                            .collect(),
                    )
                }),
        );
    }

    fn add_key_matches(
        value: &Value,
        keys: &BTreeSet<String>,
        path: &mut FieldPath,
        matches: &mut BTreeSet<FieldPath>,
    ) {
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    let depth = path.0.len();
                    path.0
                        .push(FieldSegment::Key(key.clone()));
                    if keys.contains(key) {
                        matches.insert(path.clone());
                    }
                    Self::add_key_matches(child, keys, path, matches);
                    path.0.truncate(depth);
                }
            }
            Value::Array(array) => {
                for (index, child) in array.iter().enumerate() {
                    let depth = path.0.len();
                    path.0.push(FieldSegment::Index(index));
                    Self::add_key_matches(child, keys, path, matches);
                    path.0.truncate(depth);
                }
            }
            _ => {}
        }
    }
}

impl FieldPaths {
    fn new(paths: BTreeSet<FieldPath>) -> Self {
        let mut paths = paths.into_iter().collect::<Vec<_>>();
        paths.sort_by(FieldPath::compare_removal_order);
        Self(paths)
    }
}

impl FieldPath {
    fn from_pointer(value: &Value, pointer: &str) -> Option<Self> {
        if pointer.is_empty() {
            return Some(Self(Vec::new()));
        }

        let mut current = value;
        let mut segments = Vec::new();
        for token in pointer.strip_prefix('/')?.split('/') {
            let key = token
                .replace("~1", "/")
                .replace("~0", "~");
            let segment = match current {
                Value::Object(object) if object.contains_key(&key) => FieldSegment::Key(key),
                Value::Array(array) => {
                    let index = token.parse::<usize>().ok()?;
                    if index >= array.len() {
                        return None;
                    }
                    FieldSegment::Index(index)
                }
                _ => return None,
            };
            current = match &segment {
                FieldSegment::Key(key) => current.get(key.as_str())?,
                FieldSegment::Index(index) => current.get(*index)?,
            };
            segments.push(segment);
        }
        Some(Self(segments))
    }

    fn get_mut<'a>(&self, value: &'a mut Value) -> Option<&'a mut Value> {
        let mut current = value;
        for segment in &self.0 {
            current = match segment {
                FieldSegment::Key(key) => current.get_mut(key.as_str())?,
                FieldSegment::Index(index) => current.get_mut(*index)?,
            };
        }
        Some(current)
    }

    fn remove_from(&self, value: &mut Value) {
        let Some((last, parent)) = self.0.split_last() else {
            *value = Value::Null;
            return;
        };
        let Some(parent) = (Self(parent.to_vec())).get_mut(value) else {
            return;
        };
        match (parent, last) {
            (Value::Object(object), FieldSegment::Key(key)) => {
                object.remove(key);
            }
            (Value::Array(array), FieldSegment::Index(index)) if *index < array.len() => {
                array.remove(*index);
            }
            _ => {}
        }
    }

    fn compare_removal_order(left: &Self, right: &Self) -> std::cmp::Ordering {
        right
            .0
            .len()
            .cmp(&left.0.len())
            .then_with(|| right.cmp(left))
    }
}

impl RuleAction {
    fn apply_to(
        &self,
        event: &mut NormalizedEvent,
        path: &FieldPath,
        local_keys: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), EvaluationError> {
        match self {
            Self::Remove => path.remove_from(&mut event.0),
            Self::Replace { marker } => {
                if let Some(value) = path.get_mut(&mut event.0) {
                    *value = Value::String(marker.clone());
                }
            }
            Self::Mask { preserve } => {
                if let Some(value) = path.get_mut(&mut event.0)
                    && let Some(text) = value.as_str()
                {
                    let keep = preserve.get().min(usize::MAX as u64) as usize;
                    let preserved = text
                        .chars()
                        .take(keep)
                        .collect::<String>();
                    let masked = "*".repeat(
                        text.chars()
                            .count()
                            .saturating_sub(preserved.chars().count()),
                    );
                    *value = Value::String(format!("{preserved}{masked}"));
                }
            }
            Self::HmacSha256 { key_ref } => {
                let key = local_keys
                    .get(key_ref)
                    .ok_or(EvaluationError::MissingKey)?;
                if let Some(value) = path.get_mut(&mut event.0) {
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
