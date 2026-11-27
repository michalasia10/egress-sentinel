//! Deterministic detection of basic secrets in normalized JSON data.

use crate::validators::SECRET_VALIDATORS;
use es_core::detection::DetectionCategory;
use serde_json::Value;
use std::collections::BTreeSet;

/// A detected category and the JSON Pointer of the containing normalized field.
///
/// This type deliberately has no field for the matched value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    category: DetectionCategory,
    field: String,
}

impl Finding {
    /// Returns the detected category.
    pub fn category(&self) -> DetectionCategory {
        self.category
    }

    /// Returns the JSON Pointer of the field containing the match.
    pub fn field(&self) -> &str {
        &self.field
    }
}

/// Detects basic secret formats in string values of normalized JSON.
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretDetector;

impl SecretDetector {
    /// Scans every normalized string and returns unique category and field pairs.
    pub fn detect(&self, normalized: &Value) -> Vec<Finding> {
        let mut findings = BTreeSet::new();
        Self::visit(normalized, String::new(), &mut findings);
        findings.into_iter().collect()
    }

    fn visit(value: &Value, field: String, findings: &mut BTreeSet<Finding>) {
        match value {
            Value::Object(fields) => {
                for (name, value) in fields {
                    Self::visit(
                        value,
                        format!("{field}/{}", Self::escape_pointer(name)),
                        findings,
                    );
                }
            }
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    Self::visit(value, format!("{field}/{index}"), findings);
                }
            }
            Value::String(text) => {
                for category in Self::categories_in(text) {
                    findings.insert(Finding {
                        category,
                        field: field.clone(),
                    });
                }
            }
            _ => {}
        }
    }

    fn categories_in(text: &str) -> BTreeSet<DetectionCategory> {
        SECRET_VALIDATORS
            .iter()
            .filter(|validator| validator.matches(text))
            .map(|validator| validator.category())
            .collect()
    }

    fn escape_pointer(field: &str) -> String {
        field
            .replace('~', "~0")
            .replace('/', "~1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_secret_categories_without_returning_values() {
        let event = json!({
            "auth": {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234"},
            "provider": "sk-live-abcdefghijklmnop",
            "key": "-----BEGIN RSA PRIVATE KEY-----\nprivate bytes\n-----END RSA PRIVATE KEY-----",
            "database": "postgres://user:password@db.example.test/app"
        });

        let findings = SecretDetector.detect(&event);
        assert!(findings.contains(&Finding {
            category: DetectionCategory::Jwt,
            field: "/auth/token".to_owned()
        }));
        assert!(findings.contains(&Finding {
            category: DetectionCategory::ApiKey,
            field: "/provider".to_owned()
        }));
        assert!(findings.contains(&Finding {
            category: DetectionCategory::PrivateKey,
            field: "/key".to_owned()
        }));
        assert!(findings.contains(&Finding {
            category: DetectionCategory::ConnectionString,
            field: "/database".to_owned()
        }));
        let rendered = format!("{findings:?}");
        assert!(!rendered.contains("abcdefghijklmnop"));
        assert!(!rendered.contains("private bytes"));
        assert!(!rendered.contains("password"));
    }

    #[test]
    fn ignores_common_non_secret_values_and_escapes_field_paths() {
        let event = json!({
            "ordinary": ["hello world", "not.a.jwt"],
            "a/b~c": "just a value",
            "sensitive/name~": "ghp_abcdefghijklmnop"
        });

        let findings = SecretDetector.detect(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].field(), "/sensitive~1name~0");
    }
}
