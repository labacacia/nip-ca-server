[English Version](./README.md) | 中文版

# NIP CA Server — Java

基于 Spring Boot + SQLite 的 NIP 证书颁发机构实现（NPS-3 §8）。

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
| `PORT` | 否 | `17440` | |

## API

与其他语言的 NIP CA Server 实现共用同一组端点 —— 详见 [NPS-3 §8](../../spec/NPS-3-NIP.md)。

## 本地开发

```bash
NIP_CA_NID=urn:nps:org:ca.local \
  NIP_CA_PASSPHRASE=dev-pass \
  NIP_CA_BASE_URL=http://localhost:17440 \
  ./gradlew bootRun
```

## 技术栈

- **运行时**：Java 21（eclipse-temurin）
- **框架**：Spring Boot 3.4
- **加密**：Java 标准库（Ed25519 + AES/GCM + PBKDF2WithHmacSHA256）
- **存储**：SQLite（sqlite-jdbc）
