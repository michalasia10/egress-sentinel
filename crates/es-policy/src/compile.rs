//! Validation and compilation from policy source to the validated model.
use crate::{error::PolicyError, model::*, source::*};
use std::collections::HashSet;

/// Parses and validates a complete policy. The input is never retained in errors.
pub fn compile_yaml(source: &str) -> Result<Policy, PolicyError> {
    let raw: RawPolicy = yaml_serde::from_str(source).map_err(|_| PolicyError::Malformed)?;
    compile(raw)
}
fn compile(raw: RawPolicy) -> Result<Policy, PolicyError> {
    if raw.version != 1 {
        return Err(PolicyError::Invalid {
            field: "version",
            reason: "unsupported version",
        });
    }
    if raw.destinations.is_empty() {
        return Err(PolicyError::Invalid {
            field: "destinations",
            reason: "must not be empty",
        });
    }
    let mut ids = HashSet::new();
    let mut destinations = Vec::new();
    for d in raw.destinations {
        if d.id.trim().is_empty() {
            return Err(PolicyError::Invalid {
                field: "destinations.id",
                reason: "must not be empty",
            });
        }
        if !ids.insert(d.id.clone()) {
            return Err(PolicyError::Duplicate {
                field: "destinations.id",
            });
        }
        let protocol = match d.protocol.as_str() {
            "sentry" => Protocol::Sentry,
            _ => {
                return Err(PolicyError::Invalid {
                    field: "destinations.protocol",
                    reason: "unsupported protocol",
                });
            }
        };
        if d.allowed_hosts.is_empty() || d.allowed_hosts.iter().any(|h| !valid_host(h)) {
            return Err(PolicyError::Invalid {
                field: "destinations.allowed_hosts",
                reason: "must contain valid host names",
            });
        }
        destinations.push(Destination {
            id: d.id,
            protocol,
            allowed_hosts: d.allowed_hosts,
        });
    }
    let mut rule_ids = HashSet::new();
    let mut rules = Vec::new();
    for r in raw.rules {
        if r.id.trim().is_empty() {
            return Err(PolicyError::Invalid {
                field: "rules.id",
                reason: "must not be empty",
            });
        }
        if !rule_ids.insert(r.id.clone()) {
            return Err(PolicyError::Duplicate { field: "rules.id" });
        }
        if r.match_
            .as_ref()
            .and_then(|m| m.json_path.as_deref())
            .is_some_and(|v| v.trim().is_empty())
        {
            return Err(PolicyError::Invalid {
                field: "rules.match.json_path",
                reason: "must not be empty",
            });
        }
        if let Some(m) = &r.match_ {
            if m.paths.iter().any(|v| v.trim().is_empty()) {
                return Err(PolicyError::Invalid {
                    field: "rules.match.paths",
                    reason: "entries must not be empty",
                });
            }
            if m.key_matches.iter().any(|v| v.trim().is_empty()) {
                return Err(PolicyError::Invalid {
                    field: "rules.match.key_matches",
                    reason: "entries must not be empty",
                });
            }
        }
        let matcher = match (r.match_, r.detect) {
            (Some(m), None)
                if m.json_path.is_some() || !m.paths.is_empty() || !m.key_matches.is_empty() =>
            {
                Matcher::Match(Match {
                    json_path: m.json_path,
                    paths: m.paths,
                    key_matches: m.key_matches,
                })
            }
            (None, Some(d))
                if !d.types.is_empty() && d.types.iter().all(|v| !v.trim().is_empty()) =>
            {
                Matcher::Detect(d.types)
            }
            _ => {
                return Err(PolicyError::Invalid {
                    field: "rules",
                    reason: "must contain exactly one valid matcher",
                });
            }
        };
        let action = action(&r.action)?;
        if matches!(action, Action::HmacSha256) != r.key_ref.is_some() {
            return Err(PolicyError::Invalid {
                field: "rules.key_ref",
                reason: "required only for hmac_sha256",
            });
        }
        if matches!(action, Action::Replace) != r.marker.is_some() {
            return Err(PolicyError::Invalid {
                field: "rules.marker",
                reason: "required only for replace",
            });
        }
        if matches!(action, Action::Mask) != r.preserve.is_some() {
            return Err(PolicyError::Invalid {
                field: "rules.preserve",
                reason: "required only for mask",
            });
        }
        if matches!(action, Action::Route) != r.destination.is_some() {
            return Err(PolicyError::Invalid {
                field: "rules.destination",
                reason: "required only for route",
            });
        }
        if let Some(v) = &r.destination {
            if !ids.contains(v) {
                return Err(PolicyError::Unresolved {
                    field: "rules.destination",
                });
            }
        }
        if r.key_ref.as_deref().is_some_and(|v| v.trim().is_empty()) {
            return Err(PolicyError::Invalid {
                field: "rules.key_ref",
                reason: "must not be empty",
            });
        }
        if r.marker.as_deref().is_some_and(|v| v.trim().is_empty()) {
            return Err(PolicyError::Invalid {
                field: "rules.marker",
                reason: "must not be empty",
            });
        }
        if r.preserve == Some(0) {
            return Err(PolicyError::Invalid {
                field: "rules.preserve",
                reason: "must be positive",
            });
        }
        rules.push(Rule {
            id: r.id,
            matcher,
            action,
            key_ref: r.key_ref,
            marker: r.marker,
            preserve: r.preserve,
            destination: r.destination,
        });
    }
    let limits = limits(raw.limits)?;
    Ok(Policy {
        version: raw.version,
        destinations,
        rules,
        limits,
        security: raw.security.unwrap_or_default().into(),
    })
}
fn action(v: &str) -> Result<Action, PolicyError> {
    match v {
        "remove" => Ok(Action::Remove),
        "replace" => Ok(Action::Replace),
        "mask" => Ok(Action::Mask),
        "hmac_sha256" => Ok(Action::HmacSha256),
        "drop_event" => Ok(Action::DropEvent),
        "quarantine" => Ok(Action::Quarantine),
        "route" => Ok(Action::Route),
        _ => Err(PolicyError::Invalid {
            field: "rules.action",
            reason: "unsupported action",
        }),
    }
}
fn limits(raw: Option<RawLimits>) -> Result<Limits, PolicyError> {
    let Some(r) = raw else {
        return Ok(Limits::default());
    };
    let size = r.max_event_size.map(size).transpose()?;
    for (v, f) in [
        (r.max_string_field_length, "limits.max_string_field_length"),
        (
            r.events_per_minute_per_project,
            "limits.events_per_minute_per_project",
        ),
    ] {
        if v == Some(0) {
            return Err(PolicyError::Invalid {
                field: f,
                reason: "must be positive",
            });
        }
    }
    Ok(Limits {
        max_event_size: size,
        max_string_field_length: r.max_string_field_length,
        events_per_minute_per_project: r.events_per_minute_per_project,
    })
}
fn size(v: RawSize) -> Result<u64, PolicyError> {
    match v {
        RawSize::Bytes(n) if n > 0 => Ok(n),
        RawSize::Text(s) => {
            let s = s.trim().to_ascii_lowercase();
            let (n, m) = if let Some(v) = s.strip_suffix("kb") {
                (v, 1024)
            } else if let Some(v) = s.strip_suffix("mb") {
                (v, 1024 * 1024)
            } else if let Some(v) = s.strip_suffix('b') {
                (v, 1)
            } else {
                return Err(PolicyError::Invalid {
                    field: "limits.max_event_size",
                    reason: "must use bytes, kb, or mb",
                });
            };
            n.parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .and_then(|n| n.checked_mul(m))
                .ok_or(PolicyError::Invalid {
                    field: "limits.max_event_size",
                    reason: "must be a positive size",
                })
        }
        _ => Err(PolicyError::Invalid {
            field: "limits.max_event_size",
            reason: "must be positive",
        }),
    }
}
fn valid_host(v: &str) -> bool {
    v.is_ascii()
        && v.len() <= 253
        && v.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
impl From<RawSecurity> for Security {
    fn from(v: RawSecurity) -> Self {
        Self {
            reject_unknown_projects: v.reject_unknown_projects,
            reject_attachments: v.reject_attachments,
        }
    }
}
