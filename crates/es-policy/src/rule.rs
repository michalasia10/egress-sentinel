//! Rule declarations, matchers, and action invariants.

use serde_json_path::JsonPath;
use std::collections::HashSet;

use crate::{
    destination::DestinationCatalog,
    error::{PolicyError, RuleCause, RuleError, RuleField},
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
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Id,
                cause: RuleCause::Empty,
            }));
        }
        if !declared_ids.insert(raw.id.clone()) {
            return Err(PolicyError::Rule(RuleError::DuplicateId));
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
            _ => Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Collection,
                cause: RuleCause::InvalidMatcher,
            })),
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
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::JsonPath,
                cause: RuleCause::Empty,
            }));
        }
        if raw
            .paths
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Paths,
                cause: RuleCause::Empty,
            }));
        }
        if raw
            .key_matches
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::KeyMatches,
                cause: RuleCause::Empty,
            }));
        }
        if raw.json_path.is_none() && raw.paths.is_empty() && raw.key_matches.is_empty() {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Matcher,
                cause: RuleCause::InvalidMatcher,
            }));
        }
        let json_path = raw
            .json_path
            .map(|path| JsonPath::parse(&path))
            .transpose()
            .map_err(|_| invalid_json_path(RuleField::JsonPath))?;
        let paths = raw
            .paths
            .into_iter()
            .map(|path| JsonPath::parse(&path).map_err(|_| invalid_json_path(RuleField::Paths)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            json_path,
            paths,
            key_matches: raw.key_matches,
        })
    }
}

fn invalid_json_path(field: RuleField) -> PolicyError {
    PolicyError::Rule(RuleError::Invalid {
        field,
        cause: RuleCause::InvalidJsonPath,
    })
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
        if matches!(action, Action::HmacSha256) && key_ref.is_none() {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::KeyRef,
                cause: RuleCause::RequiredForAction(action),
            }));
        }
        if !matches!(action, Action::HmacSha256) && key_ref.is_some() {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::KeyRef,
                cause: RuleCause::ForbiddenForAction(action),
            }));
        }
        if matches!(action, Action::Replace) && marker.is_none() {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Marker,
                cause: RuleCause::RequiredForAction(action),
            }));
        }
        if !matches!(action, Action::Replace) && marker.is_some() {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Marker,
                cause: RuleCause::ForbiddenForAction(action),
            }));
        }
        if matches!(action, Action::Mask) && preserve.is_none() {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Preserve,
                cause: RuleCause::RequiredForAction(action),
            }));
        }
        if !matches!(action, Action::Mask) && preserve.is_some() {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Preserve,
                cause: RuleCause::ForbiddenForAction(action),
            }));
        }
        if matches!(action, Action::Route) && destination.is_none() {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Destination,
                cause: RuleCause::RequiredForAction(action),
            }));
        }
        if !matches!(action, Action::Route) && destination.is_some() {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Destination,
                cause: RuleCause::ForbiddenForAction(action),
            }));
        }
        if let Some(destination) = &destination
            && !destinations.contains(destination)
        {
            return Err(PolicyError::Rule(RuleError::UnresolvedDestination));
        }
        if key_ref
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::KeyRef,
                cause: RuleCause::Empty,
            }));
        }
        if marker
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Marker,
                cause: RuleCause::Empty,
            }));
        }
        if preserve == Some(0) {
            return Err(PolicyError::Rule(RuleError::Invalid {
                field: RuleField::Preserve,
                cause: RuleCause::MustBePositive,
            }));
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
