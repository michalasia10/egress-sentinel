# Product Vision

## Problem

Error events, logs, and traces routinely contain credentials, cookies,
authorization headers, request and response bodies, user identifiers, contact
details, and domain-specific sensitive values. Scrubbing is often scattered
across SDKs and vendor settings, which makes it difficult to review, test, or
prove what actually left the infrastructure.

## Product promise

Egress Sentinel is a locally operated egress-security layer for observability
traffic. A company can define one reviewed policy, apply it before forwarding
telemetry to approved backends, and retain evidence of the decision without
retaining raw telemetry by default.

The data plane runs in the customer's Docker, VM, VPC, or Kubernetes cluster.
An optional future control plane may manage policy versions and aggregate safe
metadata, but it must never be required for the local gateway to operate.

## Users

The first user is a CTO, SRE, DevOps, or platform engineer at a 10–200 person
B2B SaaS company. They use Sentry and/or OpenTelemetry, process customer data,
and need a practical answer to security reviews about observability egress.

## Principles

- **Fail closed for egress.** An unknown destination, invalid policy, or unsafe
  route does not result in an outbound request.
- **Policy as code.** Policies are YAML, reviewed in Git, validated in CI, and
  identified by immutable versions or digests.
- **No raw audit by default.** Audit records describe a decision; they do not
  reproduce the payload that triggered it.
- **Vendor-neutral core.** Sentry is the MVP protocol, not the data model of the
  entire product.
- **Deterministic first.** Field rules, regular expressions, entropy heuristics,
  and explicit schemas take precedence over opaque classification.

## Non-goals

The MVP does not replace Sentry, Loki, OpenSearch, Datadog, or an OTel backend;
store all telemetry; guarantee legal compliance; support session replay; act as
a full SIEM/DLP/CASB; or perform AI incident analysis.
