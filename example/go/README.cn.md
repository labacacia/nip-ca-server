[English Version](./README.md) | 中文版

# NIP CA Server — Go

基于 Go + SQLite 的 NIP 证书颁发机构实现（NPS-3 §8）。

## 快速开始

```bash
docker compose up -d
```

## 环境变量

| 变量 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `NIP_CA_NID` | 是 | — | CA 的 NID |
| `NIP_CA_PASSPHRASE` | 是 | — | 密钥文件口令 |
| `NIP_CA_BASE_URL` | 是 | — | 公网基础 URL |
| `NIP_CA_DISPLAY_NAME` | 否 | `NPS CA` | |
| `NIP_CA_KEY_FILE` | 否 | `/data/ca.key.enc` | |
| `NIP_CA_DB_PATH` | 否 | `/data/ca.db` | |
| `NIP_CA_AGENT_VALIDITY_DAYS` | 否 | `30` | |
| `NIP_CA_NODE_VALIDITY_DAYS` | 否 | `90` | |
| `NIP_CA_RENEWAL_WINDOW_DAYS` | 否 | `7` | |
| `NIP_CA_ROOT_CERT_FILE` | 否 | `/data/ca.root.der` | RFC-0002 自签 X.509 root 证书路径（首次启动时自动生成，5 年有效） |
| `PORT` | 否 | `17440` | |

## API

与其他语言的 NIP CA Server 实现共用同一组端点 —— 详见 [NPS-3 §8](../../spec/NPS-3-NIP.md)。

`alpha.4` 按 **NPS-RFC-0002** 新增两个 `v2` 端点，签发同时携带 v1 Ed25519 签名 **与** 2 段 X.509 链（leaf + 自签 root）的双信任 IdentFrame：

| Method | 路径 | 说明 |
|--------|------|------|
| **POST** | **`/v2/agents/register`** | NPS-RFC-0002 —— 签发双信任 v2 IdentFrame |
| **POST** | **`/v2/nodes/register`** | NPS-RFC-0002 —— node 角色 NID 同形 |

`/.well-known/nps-ca` 现公布 `cert_formats: ["v1-proprietary", "v2-x509"]` 与新增 `register_v2` 端点 URL；schema 升至 `nps_ca: "0.2"`。

`net/http` mux 上的 ACME `agent-01` server 端点暂未在 alpha.4 暴露（与 `tools/nip-ca-server/` 的 C# 参考保持对齐）；SDK 的 `nip/acme.Server` 是 ACME 的 canonical 参考实现，可单独嵌入生产部署。

## 本地开发

```bash
NIP_CA_NID=urn:nps:org:ca.local \
  NIP_CA_PASSPHRASE=dev-pass \
  NIP_CA_BASE_URL=http://localhost:17440 \
  go run .
```

## 技术栈

- **运行时**：Go 1.23+
- **框架**：`net/http`（标准库）
- **加密**：`crypto/ed25519` + `crypto/x509`（RFC-0002 X.509 builder）+ `golang.org/x/crypto/pbkdf2` + `crypto/aes` GCM
- **存储**：SQLite（`modernc.org/sqlite`，纯 Go 实现，无 CGo）
