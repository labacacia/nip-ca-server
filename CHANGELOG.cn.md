[English Version](./CHANGELOG.md) | 中文版

# 变更日志 —— NIP CA Server — .NET

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

在 NPS 达到 v1.0 稳定版之前，套件内所有仓库同步使用同一个预发布版本号。

---

## [1.0.0-alpha.4] —— 2026-04-30

### 跟随套件的协议变更

本次跟随 NPS 套件 `v1.0.0-alpha.4`。CA Server 本身代码不变 ——
v1 IdentFrame 签发接口与 alpha.3 完全一致 —— 但底层
[`LabAcacia.NPS.NIP`](https://www.nuget.org/packages/LabAcacia.NPS.NIP/)
NuGet 依赖升至 `v1.0.0-alpha.4`，带来以下能力：

- **NPS-RFC-0002 Phase A** —— `LabAcacia.NPS.NIP` 在 v1 Ed25519
  IdentFrame 旁新增 X.509 NID 证书签发（dual-trust 签名链路）。
- **NPS-RFC-0002 Phase B** —— SDK 层 ACME `agent-01` 全链路
  （`AcmeServer` / `AcmeClient`）。
- **NPS-RFC-0001 Phase 2** —— NCP 连接前导帮助函数。

服务器对外的 HTTP 接口仍是 alpha.3 的 v1 端点。X.509 签发端点
（`/v2/agents/*`）是后续添加项 —— 等 SDK 内 X.509 + ACME 运行时稳定
后再上；现在就要 X.509 的生产部署可以直接嵌入 SDK 的
`nip.acme.AcmeServer`。

---

## [1.0.0-alpha.3] —— 2026-04-26

### 新增

- 首次作为独立仓库
  [`labacacia/nip-ca-server`](https://gitee.com/labacacia/nip-ca-server)
  发布（GitHub 镜像：[`labacacia/nip-ca-server`](https://github.com/labacacia/nip-ca-server)）。
  截至 `1.0.0-alpha.2`，本服务仅作为开发 monorepo 的子目录发布。
- 新增 `example/` 目录，收录冻结在 `1.0.0-alpha.2` 的 Python、TypeScript、
  Java、Rust、Go 五种参考移植，仅供阅读，不再维护，也不发布。
- README 加入徽章、端到端的 Docker Compose 快速开始、完整环境变量表、
  完整 API 端点表、以及"与 NPS 其他部分的关系"小节。

### 变更

- 项目改为依赖已发布的
  [`LabAcacia.NPS.NIP`](https://www.nuget.org/packages/LabAcacia.NPS.NIP/)
  NuGet 包，不再使用 monorepo 内的 `<ProjectReference>`。发布仓库现在
  脱离开发 monorepo 也能独立构建。
- Dockerfile 构建上下文从 monorepo 相对路径（`../..`）改为仓库根目录，
  从发布仓的 clone 直接 `docker build .` 即可。

### 跟随套件的协议变更

本次随套件 `v1.0.0-alpha.3` 同步发布以下协议层变更：

- **RFC-0001** —— NCP 连接前导。
- **RFC-0003** —— Agent 身份保证等级（涉及 NIP）。
- **RFC-0004** —— NID 声誉日志（Phase 1，涉及 NIP）。
- **CR-0001** —— Anchor / Bridge Node 拆分（CA Server 本身对外接口
  不变，但下游 NPS-3 NIP 的措辞已同步刷新）。

完整套件级汇总见
[`NPS-Release/CHANGELOG.cn.md`](https://gitee.com/labacacia/NPS-Release/blob/main/CHANGELOG.cn.md)。

---

## [1.0.0-alpha.2] —— 2026-04-19

### 新增

- 在 NPS 套件 `1.0.0-alpha.2` 标签下首次发布 `NIP CA Server — .NET`（ASP.NET Core 10 + SQLite）。
- 遵循 [NPS-3 §8](https://gitee.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.cn.md) 的 REST API：`/v1/agents/*`、`/v1/nodes/*`、`/v1/ca/cert`、`/v1/crl`、`/.well-known/nps-ca`、`/health`。
- Ed25519 签名，AES-256-GCM + PBKDF2 密钥文件加密，SQLite 存储。
- Docker Compose 入口。
- README 新增中文副本（`README.cn.md`），两份文件顶部都带语言切换器。

---

[1.0.0-alpha.4]: https://gitee.com/labacacia/nip-ca-server/releases/tag/v1.0.0-alpha.4
[1.0.0-alpha.3]: https://gitee.com/labacacia/nip-ca-server/releases/tag/v1.0.0-alpha.3
[1.0.0-alpha.2]: https://gitee.com/labacacia/NPS-Release/releases/tag/v1.0.0-alpha.2
[1.0.0-alpha.1]: https://gitee.com/labacacia/NPS-Release/releases/tag/v1.0.0-alpha.1
