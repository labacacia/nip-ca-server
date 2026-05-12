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
| `NIP_CA_ROOT_CERT_FILE` | 否 | `/data/ca.root.der` | RFC-0002 自签 X.509 root 证书路径（首次启动自动生成，5 年有效期） |
| `PORT` | 否 | `17440` | |

## API

v1 端点（legacy）：与其他语言的 NIP CA Server 实现共用同一组端点 —— 详见 [NPS-3 §8](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.md)。

**v2 端点（NPS-RFC-0002 X.509 + Ed25519 双信任）—— alpha.4 新增**：

- `POST /v2/agents/register` —— 签发同时含 v1 Ed25519 签名 AND 2 段 X.509 链（leaf + 自签 root）的 IdentFrame，`cert_format: "v2-x509"`。
- `POST /v2/nodes/register` —— 节点角色 NID 同形态。
- `GET /.well-known/nps-ca` —— 现在公布 `cert_formats: ["v1-proprietary", "v2-x509"]` 与新增的 `register_v2` 端点 URL。

Spring app 上的 ACME `agent-01` server 端点暂不暴露（与 `tools/nip-ca-server/` 的 C# 实现保持一致）；SDK 内的 `com.labacacia.nps.nip.acme.AcmeServer` 是 ACME 的 canonical 参考实现，生产部署可独立挂载。

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
- **加密**：Java 标准库（Ed25519 + AES/GCM + PBKDF2WithHmacSHA256）+ BouncyCastle（仅用 X.509 builder API，由 `nps-java` 传递引入）
- **存储**：SQLite（sqlite-jdbc）
- **NPS SDK**：通过 Gradle composite build 依赖 `impl/java/`（`includeBuild('../../../../impl/java')`）
