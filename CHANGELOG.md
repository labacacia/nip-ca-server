English | [中文版](./CHANGELOG.cn.md)

# Changelog — NIP CA Server — .NET

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until NPS reaches v1.0 stable, every repository in the suite is synchronized to the same pre-release version tag.

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

[1.0.0-alpha.3]: https://github.com/labacacia/nip-ca-server/releases/tag/v1.0.0-alpha.3
[1.0.0-alpha.2]: https://github.com/labacacia/NPS-Release/releases/tag/v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/labacacia/NPS-Release/releases/tag/v1.0.0-alpha.1
