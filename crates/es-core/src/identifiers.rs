//! Domain-specific identifier value objects.

use crate::error::CoreError;

/// Identifier of a project in the domain model.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProjectId(String);

impl ProjectId {
    /// Creates a project identifier from a non-empty string.
    pub fn new(value: String) -> Result<Self, CoreError> {
        if value.is_empty() {
            return Err(CoreError::EmptyProjectId);
        }

        Ok(Self(value))
    }

    /// Returns the project identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated destination identifier in the domain model.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DestinationId(String);

impl DestinationId {
    /// Creates a destination identifier from a non-empty string.
    ///
    /// Single-character identifiers are valid.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::EmptyDestinationId`] when `value` is empty.
    pub fn new(value: String) -> Result<Self, CoreError> {
        if value.is_empty() {
            return Err(CoreError::EmptyDestinationId);
        }

        Ok(Self(value))
    }

    /// Returns the original destination identifier as a string slice.
    ///
    /// This does not allocate or transfer ownership of the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{DestinationId, ProjectId};
    use crate::error::CoreError;

    #[test]
    fn accepts_a_single_character_project_id() {
        let project_id = ProjectId::new("p".to_owned());

        assert_eq!(project_id.as_ref().map(ProjectId::as_str), Ok("p"));
    }

    #[test]
    fn rejects_an_empty_project_id() {
        let project_id = ProjectId::new(String::new());

        assert_eq!(project_id, Err(CoreError::EmptyProjectId));
    }

    #[test]
    fn preserves_the_original_destination_identifier() {
        let destination_id = DestinationId::new("logs-eu".to_owned());

        assert_eq!(
            destination_id.as_ref().map(DestinationId::as_str),
            Ok("logs-eu")
        );
    }

    #[test]
    fn rejects_an_empty_destination_identifier() {
        let destination_id = DestinationId::new(String::new());

        assert_eq!(destination_id, Err(CoreError::EmptyDestinationId));
    }
}
