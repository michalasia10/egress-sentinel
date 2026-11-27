//! Destination declarations and their invariants.

use std::collections::HashSet;

use crate::{
    error::PolicyError,
    model::{Destination, Protocol},
    source::RawDestination,
};

/// Owns the destinations declared by a policy and prevents duplicate IDs.
pub(super) struct DestinationCatalog {
    ids: HashSet<String>,
    values: Vec<Destination>,
}

impl DestinationCatalog {
    pub(super) fn compile(raw: Vec<RawDestination>) -> Result<Self, PolicyError> {
        if raw.is_empty() {
            return Err(PolicyError::Invalid {
                field: "destinations",
                reason: "must not be empty",
            });
        }
        let mut catalog = Self {
            ids: HashSet::new(),
            values: Vec::with_capacity(raw.len()),
        };
        for destination in raw {
            catalog.add(destination)?;
        }
        Ok(catalog)
    }

    pub(super) fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    pub(super) fn into_values(self) -> Vec<Destination> {
        self.values
    }

    fn add(&mut self, raw: RawDestination) -> Result<(), PolicyError> {
        let destination = Destination::from_raw(raw, &mut self.ids)?;
        self.values.push(destination);
        Ok(())
    }
}

impl Destination {
    fn from_raw(
        raw: RawDestination,
        declared_ids: &mut HashSet<String>,
    ) -> Result<Self, PolicyError> {
        if raw.id.trim().is_empty() {
            return Err(PolicyError::Invalid {
                field: "destinations.id",
                reason: "must not be empty",
            });
        }
        if !declared_ids.insert(raw.id.clone()) {
            return Err(PolicyError::Duplicate {
                field: "destinations.id",
            });
        }
        let protocol = match raw.protocol.as_str() {
            "sentry" => Protocol::Sentry,
            _ => {
                return Err(PolicyError::Invalid {
                    field: "destinations.protocol",
                    reason: "unsupported protocol",
                });
            }
        };
        if raw.allowed_hosts.is_empty()
            || raw
                .allowed_hosts
                .iter()
                .any(|host| !is_hostname(host))
        {
            return Err(PolicyError::Invalid {
                field: "destinations.allowed_hosts",
                reason: "must contain valid host names",
            });
        }
        Ok(Self {
            id: raw.id,
            protocol,
            allowed_hosts: raw.allowed_hosts,
        })
    }
}

fn is_hostname(value: &str) -> bool {
    value.is_ascii()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|character| character.is_ascii_alphanumeric() || character == b'-')
        })
}
