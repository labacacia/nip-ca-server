[English Version](./README.md) | 中文版

# NIP CA Server — Python

基于 FastAPI + SQLite 的 NIP 证书颁发机构实现（NPS-3 §8）。

## 快速开始

```bash
cp .env.example .env   # 填入必填环境变量
docker compose up -d
```

## 环境变量

| 变量 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `NIP_CA_NID` | 是 | — | CA 的 NID，例如 `urn:nps:org:ca.example.com` |
| `NIP_CA_PASSPHRASE` | 是 | — | 密钥文件加密口令 |
| `NIP_CA_BASE_URL` | 是 | — | 公网基础 URL，例如 `https://ca.example.com` |
| `NIP_CA_DISPLAY_NAME` | 否 | `NPS CA` | 面向用户的 CA 显示名 |
| `NIP_CA_KEY_FILE` | 否 | `/data/ca.key.enc` | 加密 CA 私钥文件路径 |
| `NIP_CA_DB_PATH` | 否 | `/data/ca.db` | SQLite 数据库路径 |
| `NIP_CA_AGENT_VALIDITY_DAYS` | 否 | `30` | Agent 证书有效期 |
| `NIP_CA_NODE_VALIDITY_DAYS` | 否 | `90` | Node 证书有效期 |
| `NIP_CA_RENEWAL_WINDOW_DAYS` | 否 | `7` | 到期前多少天开放续签 |
| `PORT` | 否 | `17440` | HTTP 端口 |

## API

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/v1/agents/register` | 注册 Agent，签发 IdentFrame |
| POST | `/v1/agents/{nid}/renew` | 续签证书 |
| POST | `/v1/agents/{nid}/revoke` | 吊销证书 |
| GET | `/v1/agents/{nid}/verify` | 验证 / OCSP 检查 |
| POST | `/v1/nodes/register` | 注册 Node，签发 IdentFrame |
| GET | `/v1/ca/cert` | 获取 CA 公钥 |
| GET | `/v1/crl` | 证书吊销列表 |
| GET | `/.well-known/nps-ca` | CA 发现文档 |
| GET | `/health` | 健康检查 |

## 本地开发

```bash
pip install -r requirements.txt
NIP_CA_NID=urn:nps:org:ca.local \
  NIP_CA_PASSPHRASE=dev-pass \
  NIP_CA_BASE_URL=http://localhost:17440 \
  uvicorn main:app --reload --port 17440
```

## 技术栈

- **运行时**：Python 3.12
- **框架**：FastAPI + Uvicorn
- **加密**：`cryptography`（Ed25519 + AES-256-GCM + PBKDF2）
- **存储**：SQLite
