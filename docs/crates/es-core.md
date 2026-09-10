# es-core

**Role:** pure domain foundation with no protocol, network, database, or CLI I/O.

It defines `ProjectId`, `DestinationId`, `PolicyVersion`, `PolicyDigest`,
`Decision`, `Outcome`, `DetectionCategory`, transformation summaries, and shared
domain errors. Newtypes prevent mixing identifiers that happen to be strings.

It does not parse YAML or JSON, access keys, execute rules, make HTTP calls, or
persist audit records. Every other crate may depend on it; it depends on no
workspace crate.
