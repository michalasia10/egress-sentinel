# ADR 0002: Separate ingress rejections from policy decisions

## Status

Accepted.

## Context

The audit model requires a policy version and policy digest for a decision.
Some requests are rejected before a project or active policy can be selected,
for example because authentication, request limits, or protocol validation
fails.

A flat decision record with optional policy fields would conflate two distinct
facts and allow incomplete policy decisions to be represented.

## Decision

`Decision` represents only processing that occurs after project selection and
policy resolution. Every `Decision` therefore has a required `PolicyVersion`
and `PolicyDigest`.

An ingress rejection is represented by a separate audit-domain model. It does
not carry policy metadata because no policy was selected. `Outcome::Rejected`
remains part of the shared audit outcome vocabulary, but it is not a valid
outcome for `Decision`.

## Consequences

`Decision` does not use optional policy version or policy digest fields. Its
construction API must prevent a rejected outcome. A later ingress-audit type
will record rejection reasons and safe request metadata without pretending that
a policy decision was made.
