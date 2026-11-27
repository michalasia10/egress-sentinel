//! Rule declarations, matchers, and action invariants.

use std::collections::HashSet;

use crate::{
    destination::DestinationCatalog,
    error::PolicyError,
    model::{Action, Match, Matcher, Rule},
    source::{RawAction, RawDetect, RawMatch, RawRule},
};

/// Owns rules in declaration order and prevents duplicate IDs.
pub(super) struct RuleCatalog {
    ids: HashSet<String>,
    values: Vec<Rule>,
}

impl RuleCatalog {
    pub(super) fn compile(
        raw: Vec<RawRule>,
        destinations: &DestinationCatalog,
    ) -> Result<Self, PolicyError> {
        let mut catalog = Self {
            ids: HashSet::new(),
            values: Vec::with_capacity(raw.len()),
        };
        for rule in raw {
            catalog.add(rule, destinations)?;
        }
        Ok(catalog)
    }

    pub(super) fn into_values(self) -> Vec<Rule> {
        self.values
    }

    fn add(&mut self, raw: RawRule, destinations: &DestinationCatalog) -> Result<(), PolicyError> {
        let rule = Rule::from_raw(raw, &mut self.ids, destinations)?;
        self.values.push(rule);
        Ok(())
    }
}

impl Rule {
    fn from_raw(
        raw: RawRule,
        declared_ids: &mut HashSet<String>,
        destinations: &DestinationCatalog,
    ) -> Result<Self, PolicyError> {
        if raw.id.trim().is_empty() {
            return Err(PolicyError::Invalid {
                field: "rules.id",
                reason: "must not be empty",
            });
        }
        if !declared_ids.insert(raw.id.clone()) {
            return Err(PolicyError::Duplicate { field: "rules.id" });
        }
        let matcher = Matcher::from_raw(raw.match_, raw.detect)?;
        let action = raw.action.into();
        RuleAction::new(
            action,
            raw.key_ref,
            raw.marker,
            raw.preserve,
            raw.destination,
            destinations,
        )
        .map(|parameters| Self {
            id: raw.id,
            matcher,
            action: parameters.action,
            key_ref: parameters.key_ref,
            marker: parameters.marker,
            preserve: parameters.preserve,
            destination: parameters.destination,
        })
    }
}

impl Matcher {
    fn from_raw(
        raw_match: Option<RawMatch>,
        raw_detect: Option<RawDetect>,
    ) -> Result<Self, PolicyError> {
        match (raw_match, raw_detect) {
            (Some(raw_match), None) => Match::from_raw(raw_match).map(Self::Match),
            (None, Some(detect))
                if !detect.types.is_empty()
                    && detect
                        .types
                        .iter()
                        .all(|value| !value.trim().is_empty()) =>
            {
                Ok(Self::Detect(detect.types))
            }
            _ => Err(PolicyError::Invalid {
                field: "rules",
                reason: "must contain exactly one valid matcher",
            }),
        }
    }
}

impl Match {
    fn from_raw(raw: RawMatch) -> Result<Self, PolicyError> {
        if raw
            .json_path
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(PolicyError::Invalid {
                field: "rules.match.json_path",
                reason: "must not be empty",
            });
        }
        if raw
            .paths
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(PolicyError::Invalid {
                field: "rules.match.paths",
                reason: "entries must not be empty",
            });
        }
        if raw
            .key_matches
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(PolicyError::Invalid {
                field: "rules.match.key_matches",
                reason: "entries must not be empty",
            });
        }
        if raw.json_path.is_none() && raw.paths.is_empty() && raw.key_matches.is_empty() {
            return Err(PolicyError::Invalid {
                field: "rules",
                reason: "must contain exactly one valid matcher",
            });
        }
        Ok(Self {
            json_path: raw.json_path,
            paths: raw.paths,
            key_matches: raw.key_matches,
        })
    }
}

struct RuleAction {
    action: Action,
    key_ref: Option<String>,
    marker: Option<String>,
    preserve: Option<u64>,
    destination: Option<String>,
}

impl RuleAction {
    fn new(
        action: Action,
        key_ref: Option<String>,
        marker: Option<String>,
        preserve: Option<u64>,
        destination: Option<String>,
        destinations: &DestinationCatalog,
    ) -> Result<Self, PolicyError> {
        if matches!(action, Action::HmacSha256) != key_ref.is_some() {
            return Err(PolicyError::Invalid {
                field: "rules.key_ref",
                reason: "required only for hmac_sha256",
            });
        }
        if matches!(action, Action::Replace) != marker.is_some() {
            return Err(PolicyError::Invalid {
                field: "rules.marker",
                reason: "required only for replace",
            });
        }
        if matches!(action, Action::Mask) != preserve.is_some() {
            return Err(PolicyError::Invalid {
                field: "rules.preserve",
                reason: "required only for mask",
            });
        }
        if matches!(action, Action::Route) != destination.is_some() {
            return Err(PolicyError::Invalid {
                field: "rules.destination",
                reason: "required only for route",
            });
        }
        if let Some(destination) = &destination
            && !destinations.contains(destination)
        {
            return Err(PolicyError::Unresolved {
                field: "rules.destination",
            });
        }
        if key_ref
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(PolicyError::Invalid {
                field: "rules.key_ref",
                reason: "must not be empty",
            });
        }
        if marker
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(PolicyError::Invalid {
                field: "rules.marker",
                reason: "must not be empty",
            });
        }
        if preserve == Some(0) {
            return Err(PolicyError::Invalid {
                field: "rules.preserve",
                reason: "must be positive",
            });
        }
        Ok(Self {
            action,
            key_ref,
            marker,
            preserve,
            destination,
        })
    }
}

impl From<RawAction> for Action {
    fn from(value: RawAction) -> Self {
        match value {
            RawAction::Remove => Self::Remove,
            RawAction::Replace => Self::Replace,
            RawAction::Mask => Self::Mask,
            RawAction::HmacSha256 => Self::HmacSha256,
            RawAction::DropEvent => Self::DropEvent,
            RawAction::Quarantine => Self::Quarantine,
            RawAction::Route => Self::Route,
        }
    }
}
