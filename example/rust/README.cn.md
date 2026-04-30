[English Version](./README.md) | 中文版

# NIP CA Server — Rust

基于 Axum + SQLite 的 NIP 证书颁发机构实现（NPS-3 §8）。

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
| `NIP_CA_ROOT_CERT_FILE` | 否 | `/data/ca.root.der` | RFC-0002 自签 X.509 root 证书路径（每次启动基于 CA 私钥重新签发，5 年有效，写到此处供外部观测用） |
| `PORT` | 否 | `17440` | |

> **Root cert 生命周期（Rust 特有）：** 与其他语言的参考端口不同，本实现每次启动都会重新签发自签 root 证书（同一 Ed25519 私钥，重新计算 `notBefore`/`notAfter`）。`NIP_CA_ROOT_CERT_FILE` 的 DER 内容每次重启都会变化——**不要 byte-pin 该文件**。请改为 pin CA 的 Ed25519 公钥，或每次重启后重新从 `/.well-known/nps-ca` 拉取。

## API

与其他语言的 NIP CA Server 实现共用同一组端点 —— 详见 [NPS-3 §8](../../spec/NPS-3-NIP.md)。

`alpha.4` 按 **NPS-RFC-0002** 新增两个 `v2` 端点，签发同时携带 v1 Ed25519 签名 **与** 2 段 X.509 链（leaf + 自签 root）的双信任 IdentFrame：

| Method | 路径 | 说明 |
|--------|------|------|
| **POST** | **`/v2/agents/register`** | NPS-RFC-0002 —— 签发双信任 v2 IdentFrame |
| **POST** | **`/v2/nodes/register`** | NPS-RFC-0002 —— node 角色 NID 同形 |

`/.well-known/nps-ca` 现公布 `cert_formats: ["v1-proprietary", "v2-x509"]` 与新增 `register_v2` 端点 URL；schema 升至 `nps_ca: "0.2"`。

axum 上的 ACME `agent-01` server 端点暂未在 alpha.4 暴露（与 `tools/nip-ca-server/` 的 C# 参考保持对齐）；SDK 的 `nps_nip::acme::AcmeServer` 是 ACME 的 canonical 参考实现，可单独嵌入生产部署。

## 本地开发

```bash
NIP_CA_NID=urn:nps:org:ca.local \
  NIP_CA_PASSPHRASE=dev-pass \
  NIP_CA_BASE_URL=http://localhost:17440 \
  cargo run
```

## 技术栈

- **运行时**：Rust stable
- **框架**：Axum 0.8 + Tokio
- **加密**：ed25519-dalek 2 + aes-gcm + pbkdf2 + sha2 + **rcgen 0.13**（RFC-0002 X.509 builder）
- **存储**：SQLite（rusqlite，bundled）
