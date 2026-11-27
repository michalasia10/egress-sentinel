//! Deterministic detection of basic secrets in normalized JSON data.

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
        let mut categories = BTreeSet::new();
        if Self::contains_jwt(text) {
            categories.insert(DetectionCategory::Jwt);
        }
        if Self::contains_api_key(text) {
            categories.insert(DetectionCategory::ApiKey);
        }
        if text.contains("-----BEGIN ") && text.contains(" PRIVATE KEY-----") {
            categories.insert(DetectionCategory::PrivateKey);
        }
        if Self::contains_connection_string(text) {
            categories.insert(DetectionCategory::ConnectionString);
        }
        categories
    }

    fn contains_jwt(text: &str) -> bool {
        text.split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
        })
        .any(|candidate| {
            let mut parts = candidate.split('.');
            matches!((parts.next(), parts.next(), parts.next(), parts.next()),
                    (Some(header), Some(payload), Some(signature), None)
                    if Self::base64url_segment(header) && Self::base64url_segment(payload)
                        && Self::base64url_segment(signature) && signature.len() >= 8)
        })
    }

    fn base64url_segment(segment: &str) -> bool {
        segment.len() >= 4
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'='))
    }

    fn contains_api_key(text: &str) -> bool {
        [
            "sk-",
            "ghp_",
            "github_pat_",
            "glpat-",
            "xoxb-",
            "xoxp-",
            "AKIA",
        ]
        .iter()
        .any(|prefix| {
            text.match_indices(prefix)
                .any(|(index, matched)| {
                    let token = &text[index + matched.len()..];
                    let length = token
                        .bytes()
                        .take_while(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                        })
                        .count();
                    length >= 12
                })
        })
    }

    fn contains_connection_string(text: &str) -> bool {
        [
            "postgres://",
            "postgresql://",
            "mysql://",
            "mongodb://",
            "mongodb+srv://",
            "redis://",
            "amqp://",
        ]
        .iter()
        .any(|scheme| {
            text.to_ascii_lowercase()
                .contains(scheme)
        }) || (text.contains("://") && text.contains('@') && text.contains(':'))
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
