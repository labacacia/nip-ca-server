English | [中文版](./README.cn.md)

# NIP CA Server — Java

Spring Boot + SQLite implementation of the NIP Certificate Authority (NPS-3 §8).

## Quick Start

```bash
docker compose up -d
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NIP_CA_NID` | Yes | — | CA NID |
| `NIP_CA_PASSPHRASE` | Yes | — | Key file passphrase |
| `NIP_CA_BASE_URL` | Yes | — | Public base URL |
| `NIP_CA_DISPLAY_NAME` | No | `NPS CA` | |
| `NIP_CA_KEY_FILE` | No | `/data/ca.key.enc` | |
| `NIP_CA_DB_PATH` | No | `/data/ca.db` | |
| `NIP_CA_AGENT_VALIDITY_DAYS` | No | `30` | |
| `NIP_CA_NODE_VALIDITY_DAYS` | No | `90` | |
| `NIP_CA_RENEWAL_WINDOW_DAYS` | No | `7` | |
| `NIP_CA_ROOT_CERT_FILE` | No | `/data/ca.root.der` | RFC-0002 self-signed X.509 root cert (auto-generated on first boot, 5-year validity) |
| `PORT` | No | `17440` | |

## API

Legacy v1 endpoints: same as all other NIP CA Server implementations — see [NPS-3 §8](../../spec/NPS-3-NIP.md).

**v2 endpoints (NPS-RFC-0002 X.509 + Ed25519 dual-trust)** — alpha.4 addition:

- `POST /v2/agents/register` — issues an IdentFrame carrying both the v1 Ed25519 signature AND a 2-cert X.509 chain (leaf + self-signed root), `cert_format: "v2-x509"`.
- `POST /v2/nodes/register` — same shape for node-role NIDs.
- `GET /.well-known/nps-ca` — now advertises `cert_formats: ["v1-proprietary", "v2-x509"]` and the new `register_v2` endpoint URL.

ACME `agent-01` server endpoints on the Spring app are not exposed in alpha.4 (matches `tools/nip-ca-server/` C# parity); the SDK's `com.labacacia.nps.nip.acme.AcmeServer` is the canonical reference for ACME and can be embedded in production deployments separately.

## Local Development

```bash
NIP_CA_NID=urn:nps:org:ca.local \
  NIP_CA_PASSPHRASE=dev-pass \
  NIP_CA_BASE_URL=http://localhost:17440 \
  ./gradlew bootRun
```

## Stack

- **Runtime**: Java 21 (eclipse-temurin)
- **Framework**: Spring Boot 3.4
- **Crypto**: Java stdlib (Ed25519 + AES/GCM + PBKDF2WithHmacSHA256) + BouncyCastle (X.509 builder API only, transitive via `nps-java`)
- **Storage**: SQLite via sqlite-jdbc
- **NPS SDK**: depends on `impl/java/` via Gradle composite build (`includeBuild('../../../../impl/java')`)
