# es-core

**Role:** pure domain foundation with no protocol, network, database, or CLI I/O.

It defines `ProjectId`, `DestinationId`, `PolicyVersion`, `PolicyDigest`,
`PolicyRevision`, `RuleId`, `SourceProtocol`, `PayloadSizeBytes`, `Decision`,
`Outcome`, `DetectionCategory`, and shared domain errors. Newtypes prevent
mixing identifiers or audit values that happen to have the same primitive type.

`AppliedRule` and `AppliedAction` are safe summaries of transformations applied
by policy evaluation. A `Decision` records its source protocol, payload size,
selected policy revision, applied rules, and detection categories. It never
stores a raw payload or the matched values of secrets.

It does not parse YAML or JSON, access keys, execute rules, make HTTP calls, or
persist audit records. Every other crate may depend on it; it depends on no
workspace crate.
