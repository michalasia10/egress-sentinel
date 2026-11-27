//! Deterministic detection of basic secrets in normalized JSON data.

use crate::validators::{RULES, is_well_formed_jwt};
use es_core::detection::DetectionCategory;
use regex::RegexSet;
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
#[derive(Debug)]
pub struct SecretDetector {
    rules: RegexSet,
}

impl SecretDetector {
    /// Compiles the built-in detection rule set.
    ///
    /// Rule compilation happens when the detector is initialized, so an invalid
    /// built-in expression fails visibly instead of silently disabling detection.
    pub fn new() -> Result<Self, regex::Error> {
        let rules = RegexSet::new(RULES.iter().map(|rule| rule.pattern))?;
        Ok(Self { rules })
    }

    /// Scans every normalized string and returns unique category and field pairs.
    pub fn detect(&self, normalized: &Value) -> Vec<Finding> {
        let mut findings = BTreeSet::new();
        self.visit(normalized, String::new(), &mut findings);
        findings.into_iter().collect()
    }

    fn visit(&self, value: &Value, field: String, findings: &mut BTreeSet<Finding>) {
        match value {
            Value::Object(fields) => {
                for (name, value) in fields {
                    self.visit(
                        value,
                        format!("{field}/{}", Self::escape_pointer(name)),
                        findings,
                    );
                }
            }
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    self.visit(value, format!("{field}/{index}"), findings);
                }
            }
            Value::String(text) => {
                for category in self.categories_in(text) {
                    findings.insert(Finding {
                        category,
                        field: field.clone(),
                    });
                }
            }
            _ => {}
        }
    }

    fn categories_in(&self, text: &str) -> BTreeSet<DetectionCategory> {
        self.rules
            .matches(text)
            .iter()
            .filter_map(|index| {
                let rule = &RULES[index];
                (rule.category != DetectionCategory::Jwt || is_well_formed_jwt(text))
                    .then_some(rule.category)
            })
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

    fn detector() -> Option<SecretDetector> {
        let detector = SecretDetector::new();
        assert!(detector.is_ok());
        detector.ok()
    }

    #[test]
    fn detects_secret_categories_without_returning_values() {
        let event = json!({
            "auth": {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234"},
            "provider": format!("{}{}", "sk_live_", "abcdefghijklmnopqrstuvwx"),
            "key": "-----BEGIN RSA PRIVATE KEY-----\nprivate bytes\n-----END RSA PRIVATE KEY-----",
            "database": "postgres://user:password@db.example.test/app"
        });

        let Some(detector) = detector() else {
            return;
        };
        let findings = detector.detect(&event);
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
        assert!(!rendered.contains("abcdefghijklmnopqrstuvwx"));
        assert!(!rendered.contains("private bytes"));
        assert!(!rendered.contains("password"));
    }

    #[test]
    fn ignores_common_non_secret_values_and_escapes_field_paths() {
        let event = json!({
            "ordinary": ["hello world", "not.a.jwt"],
            "a/b~c": "just a value",
            "sensitive/name~": "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        });

        let Some(detector) = detector() else {
            return;
        };
        let findings = detector.detect(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].field(), "/sensitive~1name~0");
    }

    #[test]
    fn detects_additional_provider_formats_without_reporting_match_text() {
        let event = json!({
            "aws": "AKIAIOSFODNN7EXAMPLE",
            "github": "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
            "ssh": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "mongo": "mongodb+srv://service:password@cluster.example.test/db"
        });

        let Some(detector) = detector() else {
            return;
        };
        let findings = detector.detect(&event);
        assert!(findings.contains(&Finding {
            category: DetectionCategory::ApiKey,
            field: "/aws".to_owned()
        }));
        assert!(findings.contains(&Finding {
            category: DetectionCategory::ApiKey,
            field: "/github".to_owned()
        }));
        assert!(findings.contains(&Finding {
            category: DetectionCategory::PrivateKey,
            field: "/ssh".to_owned()
        }));
        assert!(findings.contains(&Finding {
            category: DetectionCategory::ConnectionString,
            field: "/mongo".to_owned()
        }));
        let rendered = format!("{findings:?}");
        assert!(!rendered.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!rendered.contains("ghp_"));
        assert!(!rendered.contains("password"));
    }

    #[test]
    fn rejects_provider_lookalikes_and_noncredential_urls() {
        let event = json!({
            "aws": "akiaiosfodnn7example",
            "url": "https://example.test/path",
            "key": "-----BEGIN PUBLIC KEY-----",
            "revision": "0123456789abcdef0123456789abcdef01234567"
        });

        let Some(detector) = detector() else {
            return;
        };
        assert!(detector.detect(&event).is_empty());
    }
}
