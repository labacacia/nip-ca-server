English | [中文版](./CHANGELOG.cn.md)

# Changelog — NIP CA Server — Python

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until NPS reaches v1.0 stable, every repository in the suite is synchronized to the same pre-release version tag.

---

## [1.0.0-alpha.2] — 2026-04-19

### Added

- First release of `NIP CA Server — Python` (FastAPI + SQLite) under the NPS suite `1.0.0-alpha.2` umbrella tag.
- REST API surface per [NPS-3 §8](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.md): `/v1/agents/*`, `/v1/nodes/*`, `/v1/ca/cert`, `/v1/crl`, `/.well-known/nps-ca`, `/health`.
- Ed25519 signing, AES-256-GCM + PBKDF2 key file encryption, SQLite-backed storage.
- Docker Compose entrypoint.
- README gained a Chinese counterpart (`README.cn.md`) with a language switcher at the top of both files.

---

[1.0.0-alpha.2]: https://github.com/LabAcacia/nps/releases/tag/v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/LabAcacia/nps/releases/tag/v1.0.0-alpha.1
