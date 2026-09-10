# ADR 0001: Local policy-first data plane

## Status

Accepted.

## Context

The gateway processes telemetry that can include sensitive customer data. A
hosted management service would create a second data-exposure path and make
offline and GitOps deployments harder.

## Decision

The local data plane validates and enforces policy independently. Raw telemetry
does not leave the customer environment except through an approved sanitized
destination. Any future control plane is optional and receives only explicitly
defined safe metadata.

## Consequences

The first release can be adopted without SaaS trust. Configuration distribution,
fleet management, and dashboards are deferred rather than becoming runtime
dependencies of the security boundary.
