[English Version](./CHANGELOG.md) | 中文版

# 变更日志 —— NIP CA Server — .NET

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

在 NPS 达到 v1.0 稳定版之前，套件内所有仓库同步使用同一个预发布版本号。

---

## [1.0.0-alpha.6] —— 2026-05-14

### 新增

- **Orchestrator group + session NID 端点（NPS-CR-0003）**：新增四条 HTTP 路由。
  `POST /v1/orchestrators/groups/register`（Operator 鉴权）签发长期 group NID，
  `lineage.role = "group"`；`POST /v1/orchestrators/groups/{nid}/sessions/issue`
  签发短期 session NID（默认 1 小时，最长 24 小时），通过签名 `lineage` 关联 group；
  session 签发端点同时接受 Operator API key Bearer（plain JSON）或 group-JWS
  （`Content-Type: application/jose+json`，`alg=EdDSA`，`nps-purpose=session-issue`）。
  `POST /v1/orchestrators/groups/{nid}/revoke` 吊销 group 并级联吊销旗下所有活跃
  session（原因 `parent_revoked`）。
  `GET /v1/orchestrators/groups/{nid}/sessions` 列出 session 供审计。
  `/.well-known/nps-ca` 广播 `"orchestrator-group"` capability。

- **数据库迁移 `db/002_orchestrator_session.sql`**：幂等脚本——新增
  `nid_role` / `parent_nid` / `lineage_json` 列，以及 `parent_nid` 的部分索引
  和将 `nid_role` 绑定到规范定义值的 `CHECK` 约束。**升级二进制前请先执行此迁移**
  ——新代码路径在每次 group / session 注册时写入新列。

- **`NIP-CERT-PARENT-REVOKED` 链式检查**：`GET /v1/agents/{nid}/verify` 现在执行
  NPS-3 §7 步骤 3a 的父级查找。group 已被吊销的 session 会被拒绝并返回新错误码，
  无论级联 DB 更新是否已落盘（纵深防御）。

- **`/metrics` 限制于管理端口 17436（fix #58）**：公共 CA 端口（17435）不再提供 `/metrics`。专用管理端口（17436，默认仅监听本地回环）提供 `/metrics`、`/healthz`、`/readyz`。访问 metrics 需要 bearer token（`NIPCA__METRICSBEARERTOKEN` 或 `NIPCA__OPERATORAPIKEY`）。

- **可观测性基线**：`/healthz`（存活探针，含 SIGTERM 排空门控）、`/readyz`（就绪探针，含存储 + 密钥材料检查）、`/metrics`（Prometheus，CA 签发计数器）。结构化 JSON 日志，通过 `NPS_LOG_LEVEL` 控制级别。

- **ACME `agent-01` 端点**（`NipCaOptions.AcmeEnabled`）：可选启用，用于自动化 NID 证书签发的 ACME 挑战处理器。

- **`NipCaOptions.OperatorApiKey`**：操作员 API 密钥，用于 metrics bearer 认证和管理操作。

### 变更

- **`generateKeyIfMissing` 现在仅在 `IsDevelopment()` 时生效**：生产环境必须提供已有的加密密钥；自动生成仅限开发环境。

- **`appsettings.Docker.json` — Kestrel 配置迁移至代码**：静态 `Kestrel.Endpoints.Http` 节已替换为 `NipCa.MgmtAddr`（`0.0.0.0:17436`）；17435 端口现在通过代码绑定。

- **版本升级至 `1.0.0-alpha.6`** —— `LabAcacia.NPS.NIP` 及新增的 `LabAcacia.NPS.Daemon.Observability` 依赖均更新至 `1.0.0-alpha.6`。

### 跟随套件

本次跟随 NPS 套件 `v1.0.0-alpha.6`，依赖 `LabAcacia.NPS.NIP` ≥ `1.0.0-alpha.6`
（新增 `IdentFrame.lineage`、`NipCaService.RegisterGroupAsync` / `IssueSessionAsync`、
JWS 验证器以及 SQLite + PostgreSQL 存储扩展）。

---

## [1.0.0-alpha.5] —— 2026-05-01

### 新增

- **SQLite 后端 `AddNipCaWithSqlite()`**：`LabAcacia.NPS.NIP` 新增
  `SqliteNipCaStore` 及 DI 扩展 `AddNipCaWithSqlite(configure, connectionString)`，
  支持无 PostgreSQL sidecar 的单二进制 / 嵌入式 CA 部署。独立 NIP CA Server
  二进制仍使用 PostgreSQL；新 API 面向直接嵌入 `LabAcacia.NPS.NIP` 库的应用。
  关联 [labacacia/NPS-Dev#19](https://github.com/labacacia/NPS-Dev/issues/19)。

- **可插拔 `INipCaStore` 注入**：新增 `AddNipCa(configure, INipCaStore store)` 重载，
  接受任意证书存储实现，便于无数据库环境下测试或接入自定义存储后端。
  关联 [labacacia/NPS-Dev#18](https://github.com/labacacia/NPS-Dev/issues/18)。

### 跟随套件

本次跟随 NPS 套件 `v1.0.0-alpha.5`。CA Server 本身代码不变 ——
v1 IdentFrame 签发接口与 alpha.4 完全一致 —— 但底层 NuGet 依赖升级：

- `LabAcacia.NPS.NIP` `1.0.0-alpha.5` 在 NIP 能力注册表（NIP v0.6）
  中新增 `topology:read`，修复 `assurance_level` 空字符串处理，
  并加入 NWP 错误码常量。同时将 wire 字段
  `estimated_npt → cgn_est`（NPS-Dev#17）在协议层完成重命名。

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

[1.0.0-alpha.6]: https://gitee.com/labacacia/nip-ca-server/releases/tag/v1.0.0-alpha.6
[1.0.0-alpha.5]: https://gitee.com/labacacia/nip-ca-server/releases/tag/v1.0.0-alpha.5
[1.0.0-alpha.4]: https://gitee.com/labacacia/nip-ca-server/releases/tag/v1.0.0-alpha.4
[1.0.0-alpha.3]: https://gitee.com/labacacia/nip-ca-server/releases/tag/v1.0.0-alpha.3
[1.0.0-alpha.2]: https://gitee.com/labacacia/NPS-Release/releases/tag/v1.0.0-alpha.2
[1.0.0-alpha.1]: https://gitee.com/labacacia/NPS-Release/releases/tag/v1.0.0-alpha.1
