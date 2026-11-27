//! Sends sanitized Sentry envelopes to named, policy-approved destinations.
//!
//! The request target is derived only from the validated destination host and
//! project identifier. Redirects are disabled so an upstream cannot redirect
//! a request to a different host.

use std::time::Duration;

use es_core::identifiers::{DestinationId, ProjectId};
use es_policy::{Destination, Protocol};
use reqwest::{Client, StatusCode, Url, redirect::Policy};
use thiserror::Error;

/// An outbound HTTP client with a fixed timeout and no redirect handling.
#[derive(Clone, Debug)]
pub struct Forwarder {
    client: Client,
}

/// Bytes representing an event after policy sanitization.
///
/// Callers should construct this only from the policy engine's sanitized
/// output. The forwarder never accepts a client-supplied URL or headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedPayload(Vec<u8>);

impl SanitizedPayload {
    /// Wraps bytes produced by the policy sanitization stage.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the payload bytes for protocol-specific request construction.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Safe result metadata returned after an upstream response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardReceipt {
    /// HTTP status returned by the approved upstream.
    pub status: StatusCode,
}

/// Failures that can occur while delivering a sanitized payload.
#[derive(Debug, Error)]
pub enum ForwardError {
    /// The configured timeout must be greater than zero.
    #[error("forwarding timeout must be greater than zero")]
    InvalidTimeout,
    /// The destination does not support this request protocol.
    #[error("destination protocol is unsupported")]
    UnsupportedProtocol,
    /// The selected destination identifier does not match the supplied destination.
    #[error("selected destination does not match the configured destination")]
    DestinationMismatch,
    /// The destination host is invalid or is not in its own allow-list.
    #[error("destination host is invalid or not approved")]
    UnapprovedHost,
    /// The upstream returned a non-success response.
    #[error("upstream rejected the request with status {0}")]
    UpstreamStatus(StatusCode),
    /// The request timed out.
    #[error("upstream request timed out")]
    Timeout,
    /// The request could not be completed.
    #[error("upstream request failed")]
    Transport,
}

impl Forwarder {
    /// Creates a client that never follows upstream redirects.
    pub fn new(timeout: Duration) -> Result<Self, ForwardError> {
        if timeout.is_zero() {
            return Err(ForwardError::InvalidTimeout);
        }

        let client = Client::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| ForwardError::Transport)?;

        Ok(Self { client })
    }

    /// Forwards a sanitized Sentry envelope to the selected named destination.
    ///
    /// The URL scheme and path are fixed, and the host must occur in the
    /// destination's validated allow-list. The project ID is added as one URL
    /// path segment, so it cannot alter the request target.
    pub async fn forward(
        &self,
        selected_destination: &DestinationId,
        destination: &Destination,
        approved_host: &str,
        project_id: &ProjectId,
        payload: SanitizedPayload,
    ) -> Result<ForwardReceipt, ForwardError> {
        if destination.id != selected_destination.as_str() {
            return Err(ForwardError::DestinationMismatch);
        }
        if destination.protocol != Protocol::Sentry {
            return Err(ForwardError::UnsupportedProtocol);
        }

        if !is_valid_hostname(approved_host)
            || !destination
                .allowed_hosts
                .iter()
                .any(|host| host.eq_ignore_ascii_case(approved_host))
        {
            return Err(ForwardError::UnapprovedHost);
        }

        let mut url = Url::parse(&format!("https://{approved_host}/api/"))
            .map_err(|_| ForwardError::UnapprovedHost)?;
        url.path_segments_mut()
            .map_err(|_| ForwardError::UnapprovedHost)?
            .push(project_id.as_str())
            .push("envelope");

        let response = self
            .client
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-sentry-envelope",
            )
            .body(payload.0)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    ForwardError::Timeout
                } else {
                    ForwardError::Transport
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(ForwardError::UpstreamStatus(status));
        }

        Ok(ForwardReceipt { status })
    }
}

fn is_valid_hostname(host: &str) -> bool {
    host.is_ascii()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|character| character.is_ascii_alphanumeric() || character == b'-')
        })
}
