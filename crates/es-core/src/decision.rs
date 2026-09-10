//! Domain types that describe a policy decision.

/// The final outcome of handling a payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The payload was forwarded to its destination.
    Forwarded,
    /// The payload was intentionally discarded.
    Dropped,
    /// The payload was not forwarded externally and its decision was recorded safely.
    ///
    /// This outcome does not guarantee that the payload itself is retained locally.
    Quarantined,
    /// The payload was refused at ingress because of authentication, rate limits, or protocol or schema validation.
    Rejected,
    /// Processing the payload could not be completed.
    Failed,
}
