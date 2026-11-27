//! Rule declarations, matchers, and action invariants.

use serde_json_path::JsonPath;
use std::collections::HashSet;

use crate::{
    destination::DestinationCatalog,
    error::{PolicyError, RuleCause, RuleError, RuleField},
    model::{Action, Match, Matcher, Rule, RuleAction},
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
        RuleAction::from_raw(
            action,
            raw.key_ref,
            raw.marker,
            raw.preserve,
            raw.destination,
            destinations,
        )
        .map(|action| Self {
            id: raw.id,
            matcher,
            action,
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

impl RuleAction {
    fn from_raw(
        action: Action,
        key_ref: Option<String>,
        marker: Option<String>,
        preserve: Option<u64>,
        destination: Option<String>,
        destinations: &DestinationCatalog,
    ) -> Result<Self, PolicyError> {
        for (field, present, required) in [
            (
                RuleField::KeyRef,
                key_ref.is_some(),
                action == Action::HmacSha256,
            ),
            (
                RuleField::Marker,
                marker.is_some(),
                action == Action::Replace,
            ),
            (
                RuleField::Preserve,
                preserve.is_some(),
                action == Action::Mask,
            ),
            (
                RuleField::Destination,
                destination.is_some(),
                action == Action::Route,
            ),
        ] {
            if present != required {
                return Err(PolicyError::Rule(RuleError::Invalid {
                    field,
                    cause: if required {
                        RuleCause::RequiredForAction(action)
                    } else {
                        RuleCause::ForbiddenForAction(action)
                    },
                }));
            }
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
            return Err(invalid_action_parameter(
                RuleField::KeyRef,
                RuleCause::Empty,
            ));
        }
        if marker
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(invalid_action_parameter(
                RuleField::Marker,
                RuleCause::Empty,
            ));
        }
        if preserve == Some(0) {
            return Err(invalid_action_parameter(
                RuleField::Preserve,
                RuleCause::MustBePositive,
            ));
        }

        let required = |field| {
            PolicyError::Rule(RuleError::Invalid {
                field,
                cause: RuleCause::RequiredForAction(action),
            })
        };
        match action {
            Action::Remove => Ok(Self::Remove),
            Action::Replace => Ok(Self::Replace {
                marker: marker.ok_or_else(|| required(RuleField::Marker))?,
            }),
            Action::Mask => {
                let preserve = preserve.ok_or_else(|| required(RuleField::Preserve))?;
                let preserve = std::num::NonZeroU64::new(preserve).ok_or_else(|| {
                    invalid_action_parameter(RuleField::Preserve, RuleCause::MustBePositive)
                })?;
                Ok(Self::Mask { preserve })
            }
            Action::HmacSha256 => Ok(Self::HmacSha256 {
                key_ref: key_ref.ok_or_else(|| required(RuleField::KeyRef))?,
            }),
            Action::DropEvent => Ok(Self::DropEvent),
            Action::Quarantine => Ok(Self::Quarantine),
            Action::Route => Ok(Self::Route {
                destination: destination.ok_or_else(|| required(RuleField::Destination))?,
            }),
        }
    }
}

fn invalid_action_parameter(field: RuleField, cause: RuleCause) -> PolicyError {
    PolicyError::Rule(RuleError::Invalid { field, cause })
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
