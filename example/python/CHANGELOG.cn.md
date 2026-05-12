[English Version](./CHANGELOG.md) | 中文版

# 变更日志 —— NIP CA Server — Python

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

在 NPS 达到 v1.0 稳定版之前，套件内所有仓库同步使用同一个预发布版本号。

---

## [1.0.0-alpha.2] —— 2026-04-19

### Added

- 在 NPS 套件 `1.0.0-alpha.2` 标签下首次发布 `NIP CA Server — Python`（FastAPI + SQLite）。
- 遵循 [NPS-3 §8](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.md) 的 REST API：`/v1/agents/*`、`/v1/nodes/*`、`/v1/ca/cert`、`/v1/crl`、`/.well-known/nps-ca`、`/health`。
- Ed25519 签名，AES-256-GCM + PBKDF2 密钥文件加密，SQLite 存储。
- Docker Compose 入口。
- README 新增中文副本（`README.cn.md`），两份文件顶部都带语言切换器。

---

[1.0.0-alpha.2]: https://github.com/LabAcacia/nps/releases/tag/v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/LabAcacia/nps/releases/tag/v1.0.0-alpha.1
