English | [中文版](./CHANGELOG.cn.md)

# Changelog — NIP CA Server — .NET

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until NPS reaches v1.0 stable, every repository in the suite is synchronized to the same pre-release version tag.

---

## [1.0.0-alpha.6] — 2026-05-12

### Added

- **Orchestrator group + session NID endpoints (NPS-CR-0003)**: Four new HTTP routes:
  `POST /v1/orchestrators/groups/register` (Operator-authed) mints a longer-lived
  group NID with `lineage.role = "group"`; `POST /v1/orchestrators/groups/{nid}/sessions/issue`
  mints short-lived session NIDs (default 1 hour, max 24 hours) chained to the
  group via signed `lineage`; the session-issue endpoint accepts EITHER an
  Operator-API-key Bearer (plain JSON body) OR a flattened group-JWS
  (`Content-Type: application/jose+json`, `alg=EdDSA`, `nps-purpose=session-issue`).
  `POST /v1/orchestrators/groups/{nid}/revoke` revokes the group AND cascades to
  every live session under it (reason `parent_revoked`).
  `GET /v1/orchestrators/groups/{nid}/sessions` lists sessions for audit.
  `/.well-known/nps-ca` advertises `"orchestrator-group"` capability.

- **Database migration `db/002_orchestrator_session.sql`**: Idempotent — adds
  `nid_role` / `parent_nid` / `lineage_json` columns plus a partial index on
  `parent_nid` and a `CHECK` constraint binding `nid_role` to the spec-defined
  values. **Apply this migration before upgrading the binary** — the new code
  paths write the new columns on every group / session registration.

- **`NIP-CERT-PARENT-REVOKED` chain check**: `GET /v1/agents/{nid}/verify` now
  performs the NPS-3 §7 step 3a parent lookup. Sessions whose group has been
  revoked are rejected with the new error code regardless of whether the
  cascade DB update already landed (defense-in-depth).

### Tracking the suite

This release tracks NPS suite `v1.0.0-alpha.6` and depends on
`LabAcacia.NPS.NIP` ≥ `1.0.0-alpha.6` (which adds `IdentFrame.lineage`,
`NipCaService.RegisterGroupAsync` / `IssueSessionAsync`, the JWS verifier,
and the SQLite + PostgreSQL store extensions).

---

## [1.0.0-alpha.5] — 2026-05-01

### Added

- **SQLite backend via `AddNipCaWithSqlite()`**: `LabAcacia.NPS.NIP` now ships
  `SqliteNipCaStore` and the `AddNipCaWithSqlite(configure, connectionString)` DI
  extension, enabling single-binary / embedded CA deployments without a PostgreSQL
  sidecar. The standalone NIP CA Server binary continues to use PostgreSQL; the new API
  targets applications that embed the `LabAcacia.NPS.NIP` library directly.
  Closes [labacacia/NPS-Dev#19](https://github.com/labacacia/NPS-Dev/issues/19).

- **Pluggable `INipCaStore` injection**: New `AddNipCa(configure, INipCaStore store)`
  overload accepts any certificate store implementation — useful for tests without a
  live database and for custom storage backends.
  Closes [labacacia/NPS-Dev#18](https://github.com/labacacia/NPS-Dev/issues/18).

### Tracking the suite

This release tracks NPS suite `v1.0.0-alpha.5`. The CA Server itself
ships unchanged — its v1 IdentFrame issuance surface is identical to
alpha.4 — but the underlying NuGet dependency is bumped:

- `LabAcacia.NPS.NIP` `1.0.0-alpha.5` adds `topology:read` to the NIP
  capabilities registry (NIP v0.6), fixes empty-string `assurance_level`
  handling, and includes NWP error-code constants. Renames the wire
  field `estimated_npt → cgn_est` (NPS-Dev#17) in the protocol layer.

---

## [1.0.0-alpha.4] — 2026-04-30

### Tracking the suite

This release tracks NPS suite `v1.0.0-alpha.4`. The CA Server itself
ships unchanged — its v1 IdentFrame issuance surface is identical to
alpha.3 — but the underlying
[`LabAcacia.NPS.NIP`](https://www.nuget.org/packages/LabAcacia.NPS.NIP/)
NuGet dependency is bumped to `v1.0.0-alpha.4`, which adds:

- **NPS-RFC-0002 Phase A** — X.509 NID certificates alongside v1 Ed25519
  IdentFrames in `LabAcacia.NPS.NIP` (dual-trust signing path).
- **NPS-RFC-0002 Phase B** — ACME `agent-01` round-trip
  (`AcmeServer` / `AcmeClient`) at the SDK layer.
- **NPS-RFC-0001 Phase 2** — NCP connection preamble helpers.

The server's HTTP surface remains the alpha.3 v1 endpoints. X.509
issuance endpoints (`/v2/agents/*`) are a future addition that will
land once the X.509 + ACME runtime has stabilised in the SDK; production
deployments wanting X.509 today should embed `nip.acme.AcmeServer` from
the SDK directly.

---

## [1.0.0-alpha.3] — 2026-04-26

### Added

- First independent release as a standalone repository at
  [`labacacia/nip-ca-server`](https://github.com/labacacia/nip-ca-server)
  (mirror: [`gitee.com/labacacia/nip-ca-server`](https://gitee.com/labacacia/nip-ca-server)).
  Up to and including `1.0.0-alpha.2`, this server shipped only as a
  subdirectory of the development monorepo.
- `example/` directory holding frozen reference ports
  (Python, TypeScript, Java, Rust, Go) carried forward from `1.0.0-alpha.2`
  for educational reading. None of these are maintained or released.
- README badges, end-to-end Docker Compose quickstart, full env-var table,
  full API surface table, and a "relationship to the rest of NPS" section.

### Changed

- Switched the project to depend on the published
  [`LabAcacia.NPS.NIP`](https://www.nuget.org/packages/LabAcacia.NPS.NIP/)
  NuGet package instead of an in-repo `<ProjectReference>`. The published
  repo is now self-contained and builds without the development monorepo.
- Dockerfile context changed from monorepo-relative (`../..`) to
  repo-root, so `docker build .` works directly from a clone of the
  publish repo.

### Tracking the suite

This release rolls up suite-wide protocol changes that landed in NPS
`v1.0.0-alpha.3`:

- **RFC-0001** — NCP connection preamble.
- **RFC-0003** — Agent identity assurance levels (touches NIP).
- **RFC-0004** — NID reputation log (Phase 1 — touches NIP).
- **CR-0001** — Anchor + Bridge Node split (no client-facing change in
  the CA Server itself, but downstream NPS-3 NIP wording was refreshed).

See [`NPS-Release/CHANGELOG.md`](https://github.com/labacacia/NPS-Release/blob/main/CHANGELOG.md)
for the full suite-level rollup.

---

## [1.0.0-alpha.2] — 2026-04-19

### Added

- First release of `NIP CA Server — .NET` (ASP.NET Core 10 + SQLite) under the NPS suite `1.0.0-alpha.2` umbrella tag.
- REST API surface per [NPS-3 §8](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.md): `/v1/agents/*`, `/v1/nodes/*`, `/v1/ca/cert`, `/v1/crl`, `/.well-known/nps-ca`, `/health`.
- Ed25519 signing, AES-256-GCM + PBKDF2 key file encryption, SQLite-backed storage.
- Docker Compose entrypoint.
- README gained a Chinese counterpart (`README.cn.md`) with a language switcher at the top of both files.

---

[1.0.0-alpha.5]: https://github.com/labacacia/nip-ca-server/releases/tag/v1.0.0-alpha.5
[1.0.0-alpha.4]: https://github.com/labacacia/nip-ca-server/releases/tag/v1.0.0-alpha.4
[1.0.0-alpha.3]: https://github.com/labacacia/nip-ca-server/releases/tag/v1.0.0-alpha.3
[1.0.0-alpha.2]: https://github.com/labacacia/NPS-Release/releases/tag/v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/labacacia/NPS-Release/releases/tag/v1.0.0-alpha.1
