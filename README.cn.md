[English Version](./README.md) | 中文版

# NIP CA Server

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](./LICENSE)
[![NuGet](https://img.shields.io/nuget/v/LabAcacia.NPS.NIP.svg?label=LabAcacia.NPS.NIP)](https://www.nuget.org/packages/LabAcacia.NPS.NIP/)
[![GitHub Release](https://img.shields.io/github/v/release/labacacia/nip-ca-server?include_prereleases)](https://github.com/labacacia/nip-ca-server/releases)
[![Spec](https://img.shields.io/badge/spec-NPS--3%20%C2%A78-success)](https://gitee.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.cn.md)

面向 **Neural Identity Protocol**（NPS-3）的自托管证书颁发机构 ——
单二进制 ASP.NET Core 服务，为 NPS Agent 和 Node 颁发、续签、吊销
Ed25519 NID 证书。

这是**参考发布实现**。Python、TypeScript、Java、Rust、Go 五个额外
移植版本放在 [`example/`](./example/) 目录下作为参考阅读，不再维护。

> 源仓库：[gitee.com/labacacia/nip-ca-server](https://gitee.com/labacacia/nip-ca-server) ·
> 镜像：[github.com/labacacia/nip-ca-server](https://github.com/labacacia/nip-ca-server) ·
> 规范：[NPS-3 NIP §8](https://gitee.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.cn.md) ·
> 套件：[NPS-Release](https://gitee.com/labacacia/NPS-Release)

---

## 特性

- 按 [NPS-3 §8](https://gitee.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.cn.md) 为 Agent 和 Node 颁发 NID
- 全程使用 **Ed25519** 签名
- CA 私钥落盘采用 **AES-256-GCM + PBKDF2** 加密
- **PostgreSQL** 存储（Docker Compose 自带 Postgres 16 sidecar）；嵌入式 / 单二进制场景可通过 `AddNipCaWithSqlite()` 使用 **SQLite**
- **OCSP** + **CRL** + **`/.well-known/nps-ca`** 发现端点
- **单 Docker 镜像**，非 root 运行，内置 healthcheck
- **运营方鉴权** —— 可选 Bearer token，保护所有写入端点
- **ACME** —— 可选，支持 RFC 8555 + NPS-RFC-0002 `agent-01` 挑战（设置 `NIPCA__ACMEENABLED=true` 开启）

## 快速开始

最快路径是用自带的 `docker-compose.yml`：

```bash
git clone https://gitee.com/labacacia/nip-ca-server.git
cd nip-ca-server

cat > .env <<'EOF'
NIPCA__CANID=urn:nps:org:ca.example.com
NIPCA__BASEURL=https://ca.example.com
NIPCA__KEYPASSPHRASE=change-me-to-a-long-random-string
POSTGRES_PASSWORD=change-me-too
EOF

docker compose up -d
curl http://localhost:17435/health
```

然后让 NPS Agent / Node 用 `https://ca.example.com` 来注册和续签。

## 配置

所有密钥必须来自环境变量。非密钥的默认值写在 `appsettings.Docker.json`。

| 变量 | 必填 | 默认 | 用途 |
|------|------|------|------|
| `NIPCA__CANID` | 是 | — | CA 的 NID，如 `urn:nps:org:ca.example.com` |
| `NIPCA__KEYPASSPHRASE` | 是 | — | CA 私钥文件加密口令 |
| `NIPCA__BASEURL` | 是 | — | CA 的公开 HTTPS 基地址 |
| `CONNECTIONSTRINGS__POSTGRES` | 是 | — | Postgres 连接字符串 |
| `NIPCA__DISPLAYNAME` | 否 | `NPS CA` | 人类可读的 CA 名称 |
| `NIPCA__KEYFILEPATH` | 否 | `/data/ca.key.enc` | 加密 CA 私钥文件路径 |
| `NIPCA__AGENTCERTVALIDITYDAYS` | 否 | `30` | Agent 证书有效期 |
| `NIPCA__NODECERTVALIDITYDAYS` | 否 | `90` | Node 证书有效期 |
| `NIPCA__RENEWALWINDOWDAYS` | 否 | `7` | 到期前多少天可续签 |
| `NIPCA__NORMALIZEOCSPRESPONSETIME` | 否 | `true` | OCSP `producedAt` 取整到秒 |
| `NIPCA__OPERATORAPIKEY` | 否 | — | 写入端点所需的 Bearer token；不设置则禁用鉴权（仅限开发环境） |
| `NIPCA__ALLOWEDCAPABILITIES` | 否 | — | 可授权能力白名单（逗号分隔）；请求包含未列举能力时返回 403 |
| `NIPCA__ACMEENABLED` | 否 | `false` | 启用 ACME RFC 8555 + `agent-01` 挑战（NPS-RFC-0002） |
| `NIPCA__ACMEPATHPREFIX` | 否 | `/acme` | ACME 端点的 HTTP 路由前缀 |
| `NIPCA__MGMT_ADDR` | 否 | `127.0.0.1:17436` | 管理端口监听地址（`/metrics`、`/healthz`、`/readyz`），默认仅监听本地回环 |
| `NIPCA__METRICSBEARERTOKEN` | 否 | — | `/metrics` 端点 Bearer token；不设置时回退至 `NIPCA__OPERATORAPIKEY` |

### TLS

容器 `17435` 端口对外暴露的是明文 HTTP，请放在 nginx、Caddy 或 Traefik
后面做 TLS 卸载 —— `BASEURL` 必须指向公网 HTTPS 端点。

## API 端点

| 方法 | 路径 | 用途 |
|------|------|------|
| `POST` | `/v1/agents/register` | 注册 Agent，颁发 `IdentFrame`（Ed25519） |
| `POST` | `/v1/agents/register-x509` | 注册 Agent，颁发双信任帧（Ed25519 + X.509 链，NPS-RFC-0002） |
| `POST` | `/v1/agents/{nid}/renew` | 续签 Agent 证书 |
| `POST` | `/v1/agents/{nid}/revoke` | 吊销 Agent 证书 |
| `GET`  | `/v1/agents/{nid}/verify` | 查询 / OCSP 验证某 Agent NID |
| `POST` | `/v1/nodes/register` | 注册 Node，颁发 `IdentFrame`（Ed25519） |
| `POST` | `/v1/nodes/register-x509` | 注册 Node，颁发双信任帧（Ed25519 + X.509 链，NPS-RFC-0002） |
| `POST` | `/v1/nodes/{nid}/renew` | 续签 Node 证书 |
| `POST` | `/v1/nodes/{nid}/revoke` | 吊销 Node 证书 |
| `GET`  | `/v1/nodes/{nid}/verify` | 查询 / OCSP 验证某 Node NID |
| `GET`  | `/v1/ca/cert` | CA 公钥 |
| `GET`  | `/v1/crl` | 证书吊销列表 |
| `GET`  | `/.well-known/nps-ca` | CA 发现文档 |
| `GET`  | `/health` | 健康检查（就绪后返回 200） |

写入端点（`register`、`register-x509`、`renew`、`revoke`）在设置了 `NIPCA__OPERATORAPIKEY` 时需携带 `Authorization: Bearer <token>` 请求头。

### 管理端口端点（默认 127.0.0.1:17436）

以下端点**仅**在管理端口（`NIPCA__MGMT_ADDR`）上提供，公共 CA 端口（17435）不暴露这些路径：

| 方法 | 路径 | 用途 |
|------|------|------|
| `GET` | `/healthz` | 存活探针；SIGTERM 排空期间返回 503 |
| `GET` | `/readyz` | 就绪探针；含存储 + 密钥材料检查 |
| `GET` | `/metrics` | Prometheus metrics（需要 Bearer token） |

`/metrics` 需在请求头携带 `Authorization: Bearer <token>`，token 优先取 `NIPCA__METRICSBEARERTOKEN`，未设置时回退至 `NIPCA__OPERATORAPIKEY`。

字段级 schema 见 [NPS-3 §8](https://gitee.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.cn.md)。

## 从源码构建

```bash
dotnet restore
dotnet build -c Release
dotnet run --project NPS.NipCaServer.csproj
```

需要 .NET 10 SDK，依赖 `LabAcacia.NPS.NIP` 从 nuget.org 拉取。

## Docker 镜像

每个 release tag 都会推到 GitHub Container Registry：

```bash
docker pull ghcr.io/labacacia/nip-ca-server:1.0.0-alpha.11
```

本地构建：

```bash
docker build -t nip-ca-server:dev .
```

## 版本规则

跟随 NPS 套件统一 SemVer。NPS 1.0 之前，套件内每个组件仓库都使用相同的
`1.0.0-alpha.x` tag。逐版本说明见 [`CHANGELOG.cn.md`](./CHANGELOG.cn.md)。

## 与 NPS 其他部分的关系

| 角色 | 位置 |
|------|------|
| 规范 —— NIP 协议 | [`NPS-Release/spec/NPS-3-NIP.cn.md`](https://gitee.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.cn.md) |
| .NET NIP 客户端 SDK | [`labacacia/NPS-sdk-dotnet`](https://gitee.com/labacacia/NPS-sdk-dotnet) |
| 其他语言 NIP SDK | [`labacacia/NPS-sdk-{py,ts,java,rust,go}`](https://gitee.com/labacacia/dashboard/projects?q=NPS-sdk) |
| 套件总览 | [`labacacia/NPS-Release`](https://gitee.com/labacacia/NPS-Release) |
| 开发用 monorepo | 私有仓库 —— 发布以单向同步落到此处 |

## 许可证

Apache License 2.0，见 [`LICENSE`](./LICENSE) 和 [`NOTICE`](./NOTICE)。

版权所有 © 2026 LabAcacia（INNO LOTUS PTY LTD）。

## 贡献

欢迎提 Issue 和 PR。任何非小改动请先开 Issue 对齐范围再动手。
`example/` 下的几个移植已冻结，要接手的话见
[`example/README.cn.md`](./example/README.cn.md)。
