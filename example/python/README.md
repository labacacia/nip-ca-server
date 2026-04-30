English | [中文版](./README.cn.md)

# NIP CA Server — Python

FastAPI + SQLite implementation of the NIP Certificate Authority (NPS-3 §8).

## Quick Start

```bash
cp .env.example .env   # fill in required vars
docker compose up -d
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NIP_CA_NID` | Yes | — | CA NID, e.g. `urn:nps:org:ca.example.com` |
| `NIP_CA_PASSPHRASE` | Yes | — | Key file encryption passphrase |
| `NIP_CA_BASE_URL` | Yes | — | Public base URL, e.g. `https://ca.example.com` |
| `NIP_CA_DISPLAY_NAME` | No | `NPS CA` | Human-readable CA name |
| `NIP_CA_KEY_FILE` | No | `/data/ca.key.enc` | Encrypted CA key file path |
| `NIP_CA_DB_PATH` | No | `/data/ca.db` | SQLite database path |
| `NIP_CA_AGENT_VALIDITY_DAYS` | No | `30` | Agent certificate validity |
| `NIP_CA_NODE_VALIDITY_DAYS` | No | `90` | Node certificate validity |
| `NIP_CA_RENEWAL_WINDOW_DAYS` | No | `7` | Days before expiry that renewal opens |
| `NIP_CA_ROOT_CERT_FILE` | No | `/data/ca.root.der` | RFC-0002 self-signed X.509 root cert (auto-generated on first boot, 5-year validity) |
| `PORT` | No | `17440` | HTTP port |

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/agents/register` | Register Agent, issue v1 IdentFrame |
| POST | `/v1/agents/{nid}/renew` | Renew certificate |
| POST | `/v1/agents/{nid}/revoke` | Revoke certificate |
| GET | `/v1/agents/{nid}/verify` | Verify / OCSP check |
| POST | `/v1/nodes/register` | Register Node, issue v1 IdentFrame |
| GET | `/v1/ca/cert` | CA public key |
| GET | `/v1/crl` | Certificate Revocation List |
| **POST** | **`/v2/agents/register`** | **NPS-RFC-0002 — issue dual-trust v2 IdentFrame (v1 Ed25519 sig + 2-cert X.509 chain)** |
| **POST** | **`/v2/nodes/register`** | **NPS-RFC-0002 — same shape for node-role NIDs** |
| GET | `/.well-known/nps-ca` | CA discovery document (now advertises `cert_formats` + `register_v2` URL) |

ACME `agent-01` server endpoints on the FastAPI app are not exposed in alpha.4 (matches `tools/nip-ca-server/` C# parity); the SDK's `nps_sdk.nip.acme.AcmeServer` is the canonical reference for ACME and can be embedded in production deployments separately.
| GET | `/health` | Health check |

## Local Development

```bash
pip install -r requirements.txt
NIP_CA_NID=urn:nps:org:ca.local \
  NIP_CA_PASSPHRASE=dev-pass \
  NIP_CA_BASE_URL=http://localhost:17440 \
  uvicorn main:app --reload --port 17440
```

## Stack

- **Runtime**: Python 3.12
- **Framework**: FastAPI + Uvicorn
- **Crypto**: `cryptography` (Ed25519 + AES-256-GCM + PBKDF2)
- **Storage**: SQLite
