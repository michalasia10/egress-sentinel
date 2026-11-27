//! Curated secret-format rules and structural token validation.
//!
//! Provider patterns in this table are adapted from the MIT-licensed
//! `adventurewave-labs/secret-scan` project. See `THIRD_PARTY_NOTICES.md`.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use es_core::detection::DetectionCategory;
use serde_json::Value;

pub(super) const JWT_PATTERN: &str =
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b";

pub(super) struct Rule {
    pub(super) category: DetectionCategory,
    pub(super) pattern: &'static str,
}

/// Built-in provider patterns. IDs are intentionally omitted from findings:
/// policy consumes stable categories, and audit output must not identify values.
pub(super) const RULES: &[Rule] = &[
    // AWS access key identifiers and named secret access keys.
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"AKIA[0-9A-Z]{16}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r#"(?i)(aws[_\-]?secret[a-z0-9_\-]*|secret[_\-]?access[_\-]?key)["']?\s*[:=]\s*(?:[^"'\n]*["']([A-Za-z0-9/+=]{40})["']|([A-Za-z0-9/+=]{40}))"#,
    },
    // GitHub PATs and OAuth/user/server/refresh tokens.
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bghp_[0-9A-Za-z]{36,}",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bgh[ousr]_[0-9A-Za-z]{36,}",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bgithub_pat_[0-9A-Za-z_]{82}\b",
    },
    // Google API keys and common provider tokens.
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bAIza[0-9A-Za-z_-]{33,}",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bsk-[0-9A-Za-z]{32,48}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,}",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\b(?:sk|pk)_(?:test|live)_[0-9A-Za-z]{24,}",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\b(?:rk_(?:test|live)_[0-9A-Za-z]{24,}|whsec_[0-9A-Za-z]{32,})\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bSG\.[0-9A-Za-z_-]{22,}\.[0-9A-Za-z_-]{22,}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bxox[baprs]-[0-9A-Za-z]{10,48}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bxapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]{32,}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bSK[0-9a-fA-F]{32}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bkey-[0-9a-zA-Z]{32}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bdop_v1_[a-f0-9]{64}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bshppa_[a-fA-F0-9]{32}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bglpat-[0-9a-zA-Z_-]{20,}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\b(?:dapi[a-f0-9]{32}(?:-[0-9])?|sbp_[a-f0-9]{40})\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bhf_[A-Za-z0-9]{34,}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bnpm_[A-Za-z0-9]{36}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\blin_api_[A-Za-z0-9]{40}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bdckr_pat_[A-Za-z0-9_-]{27}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bglsa_[A-Za-z0-9]{32}_[a-f0-9]{8}\b",
    },
    Rule {
        category: DetectionCategory::PrivateKey,
        pattern: r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r#"(?i)\bheroku[a-z0-9_.-]{0,24}["']?\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#,
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r"\bAccountKey=[A-Za-z0-9+/]{86}==",
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r#"(?i)\b(?:datadog|dd)[a-z0-9_.-]{0,16}(?:api|app)[a-z0-9_.-]{0,12}key["']?\s*[:=]\s*["']?[a-f0-9]{32}(?:[a-f0-9]{8})?\b"#,
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r#"(?i)\bcloudflare[a-z0-9_.-]{0,24}["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{37,40}\b"#,
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r#"(?i)\bvercel[a-z0-9_.-]{0,24}token["']?\s*[:=]\s*["']?[A-Za-z0-9]{24}\b"#,
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r#"(?i)azure[_\s-]?(client[_\s-]?)?secret["']?\s*[:=]\s*["']?[A-Za-z0-9~._-]{34,}["']?"#,
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r#"(?i)paypal[_\s-]?secret["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{60,}["']?"#,
    },
    Rule {
        category: DetectionCategory::ApiKey,
        pattern: r#"(?i)(oauth|client)[_\s-]?secret["']?\s*[:=]\s*["']?[a-zA-Z0-9._~+/-]{32,}["']?"#,
    },
    // Private-key PEM headers include PKCS#8, DSA, encrypted, EC, RSA, OpenSSH and PGP.
    Rule {
        category: DetectionCategory::PrivateKey,
        pattern: r"-----BEGIN\s+(?:[A-Z]+\s+)*PRIVATE\s+KEY(?:\s+BLOCK)?-----",
    },
    // Credential-bearing database URLs. The user and password must both be present.
    Rule {
        category: DetectionCategory::ConnectionString,
        pattern: r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@]+@[^\s]+",
    },
    Rule {
        category: DetectionCategory::ConnectionString,
        pattern: r#"(?i)(connection[_\s-]?string|conn[_\s-]?str)["']?\s*[:=]\s*["']?[^"'\s]+"#,
    },
    Rule {
        category: DetectionCategory::ConnectionString,
        pattern: r#"(?i)(database[_\s-]?url|db[_\s-]?url)["']?\s*[:=]\s*["']?[^"'\s]+"#,
    },
    Rule {
        category: DetectionCategory::ConnectionString,
        pattern: r"(?i)://[^\s:/@]+:[^\s@]{8,}@[\w.-]+",
    },
    // JWTs receive structural validation after this prefilter match.
    Rule {
        category: DetectionCategory::Jwt,
        pattern: JWT_PATTERN,
    },
];

/// Rejects JWT-shaped strings unless the header and payload are base64url JSON
/// objects and the header contains a string `alg` field.
pub(super) fn is_well_formed_jwt_candidate(candidate: &str) -> bool {
    let mut segments = candidate.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    if signature.is_empty() {
        return false;
    }

    let Some(header) = decode_json_object(header) else {
        return false;
    };
    header
        .get("alg")
        .is_some_and(Value::is_string)
        && decode_json_object(payload).is_some()
}

fn decode_json_object(segment: &str) -> Option<serde_json::Map<String, Value>> {
    let segment = segment.trim_end_matches('=');
    let bytes = URL_SAFE_NO_PAD.decode(segment).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(object) => Some(object),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[test]
    fn every_rule_compiles() {
        assert!(regex::RegexSet::new(RULES.iter().map(|rule| rule.pattern)).is_ok());
    }

    #[test]
    fn jwt_validation_rejects_encoded_json_that_is_not_a_token() {
        let encode = |value: &str| URL_SAFE_NO_PAD.encode(value);
        let header = encode(r#"{"alg":"HS256"}"#);
        let payload = encode(r#"{"sub":"123"}"#);
        let valid = format!("{header}.{payload}.c2lnbmF0dXJl");
        assert!(is_well_formed_jwt_candidate(&valid));

        let invalid_header = encode(r#"{"typ":"JWT"}"#);
        assert!(!is_well_formed_jwt_candidate(&format!(
            "{invalid_header}.{payload}.c2lnbmF0dXJl"
        )));
        assert!(!is_well_formed_jwt_candidate(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ."
        ));
    }
}
