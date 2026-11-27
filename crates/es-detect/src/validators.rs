//! Format-specific validators used by the normalized-data detector.

use es_core::detection::DetectionCategory;

/// Validates one secret format without exposing the matched value.
pub(super) trait SecretValidator: Sync {
    fn category(&self) -> DetectionCategory;
    fn matches(&self, text: &str) -> bool;
}

struct JwtValidator;

impl SecretValidator for JwtValidator {
    fn category(&self) -> DetectionCategory {
        DetectionCategory::Jwt
    }

    fn matches(&self, text: &str) -> bool {
        text.split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
        })
        .any(|candidate| {
            let mut segments = candidate.split('.');
            matches!(
                (
                    segments.next(),
                    segments.next(),
                    segments.next(),
                    segments.next()
                ),
                (Some(header), Some(payload), Some(signature), None)
                    if is_base64url_segment(header)
                        && is_base64url_segment(payload)
                        && is_base64url_segment(signature)
                        && signature.len() >= 8
            )
        })
    }
}

struct ApiKeyValidator;

impl SecretValidator for ApiKeyValidator {
    fn category(&self) -> DetectionCategory {
        DetectionCategory::ApiKey
    }

    fn matches(&self, text: &str) -> bool {
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
                    text[index + matched.len()..]
                        .bytes()
                        .take_while(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                        })
                        .count()
                        >= 12
                })
        })
    }
}

struct PrivateKeyValidator;

impl SecretValidator for PrivateKeyValidator {
    fn category(&self) -> DetectionCategory {
        DetectionCategory::PrivateKey
    }

    fn matches(&self, text: &str) -> bool {
        text.contains("-----BEGIN ") && text.contains(" PRIVATE KEY-----")
    }
}

struct ConnectionStringValidator;

impl SecretValidator for ConnectionStringValidator {
    fn category(&self) -> DetectionCategory {
        DetectionCategory::ConnectionString
    }

    fn matches(&self, text: &str) -> bool {
        let lowercase = text.to_ascii_lowercase();
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
        .any(|scheme| lowercase.contains(scheme))
            || (text.contains("://") && text.contains('@') && text.contains(':'))
    }
}

static JWT_VALIDATOR: JwtValidator = JwtValidator;
static API_KEY_VALIDATOR: ApiKeyValidator = ApiKeyValidator;
static PRIVATE_KEY_VALIDATOR: PrivateKeyValidator = PrivateKeyValidator;
static CONNECTION_STRING_VALIDATOR: ConnectionStringValidator = ConnectionStringValidator;

pub(super) static SECRET_VALIDATORS: [&'static dyn SecretValidator; 4] = [
    &JWT_VALIDATOR,
    &API_KEY_VALIDATOR,
    &PRIVATE_KEY_VALIDATOR,
    &CONNECTION_STRING_VALIDATOR,
];

fn is_base64url_segment(segment: &str) -> bool {
    segment.len() >= 4
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'='))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validators_reject_common_non_secret_formats() {
        assert!(!JWT_VALIDATOR.matches("not.a.jwt"));
        assert!(!API_KEY_VALIDATOR.matches("sk-short"));
        assert!(!PRIVATE_KEY_VALIDATOR.matches("-----BEGIN PUBLIC KEY-----"));
        assert!(!CONNECTION_STRING_VALIDATOR.matches("https://example.test/path"));
    }
}
