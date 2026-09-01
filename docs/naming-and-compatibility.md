# NIP CA Server package and runtime compatibility decision

Status: accepted
Decision: EPIC-005-COMPAT-009
Date: 2026-09-01
Owner: NIP CA Server maintainers

## Context

The canonical repository and product are **NIP CA Server** at
`labacacia/NIP-CA-Server`. Its TypeScript reference implementation uses the
lowercase npm/runtime coordinate `@labacacia/nip-ca-server`; Docker, Compose,
service, configuration and data-path examples likewise use `nip-ca-server` or
`NIPCA_*` families.

The npm coordinate is not present in the public npm registry at decision time.
It is nevertheless a valid lowercase technical identity stored in the example
package and lockfile. Repository display casing is not a reason to invent a
second runtime identity.

## Decision

- Repository links and provenance use `labacacia/NIP-CA-Server`.
- `@labacacia/nip-ca-server` remains the TypeScript reference package/runtime
  coordinate if the reference implementation is built or published.
- Existing `nip-ca-server` image/service/container names and `NIPCA_*` /
  `NipCa:*` configuration bindings remain supported.
- The .NET `NPS.NipCaServer.*` code family and NIP protocol names remain
  unchanged.

## Alternatives considered

1. Match repository display casing in npm/runtime names — rejected because npm
   package names are lowercase and repository casing is not an operational
   naming requirement.
2. Introduce a second package/runtime coordinate — rejected because the
   reference implementation has no migration need and dual coordinates would
   create ambiguity.
3. Retain the existing lowercase runtime identity — accepted.

## Consequences and removal gate

The current coordinate remains reserved even though it is not publicly
published. A future rename requires registry availability checks, consumer and
deployment inventory, package/image forwarding or dual publication,
configuration and data migration, compatibility tests, rollback guidance and a
published support window.

These technical identifiers have no scheduled removal date.
