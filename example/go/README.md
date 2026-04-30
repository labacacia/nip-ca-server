English | [中文版](./README.cn.md)

# NIP CA Server — Go

Go + SQLite implementation of the NIP Certificate Authority (NPS-3 §8).

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

Same endpoints as all other NIP CA Server implementations — see [NPS-3 §8](../../spec/NPS-3-NIP.md).

`alpha.4` adds two `v2` endpoints per **NPS-RFC-0002** that issue dual-trust IdentFrames carrying both the v1 Ed25519 signature **and** a 2-cert X.509 chain (leaf + self-signed root):

| Method | Path | Description |
|--------|------|-------------|
| **POST** | **`/v2/agents/register`** | NPS-RFC-0002 — issue dual-trust v2 IdentFrame |
| **POST** | **`/v2/nodes/register`** | NPS-RFC-0002 — same shape for node-role NIDs |

`/.well-known/nps-ca` advertises `cert_formats: ["v1-proprietary", "v2-x509"]` and the new `register_v2` endpoint URL; schema bumped to `nps_ca: "0.2"`.

ACME `agent-01` server endpoints on the `net/http` mux are not exposed in alpha.4 (matches `tools/nip-ca-server/` C# parity); the SDK's `nip/acme.Server` is the canonical reference for ACME and can be embedded in production deployments separately.

## Local Development

```bash
NIP_CA_NID=urn:nps:org:ca.local \
  NIP_CA_PASSPHRASE=dev-pass \
  NIP_CA_BASE_URL=http://localhost:17440 \
  go run .
```

## Stack

- **Runtime**: Go 1.23+
- **Framework**: `net/http` (stdlib)
- **Crypto**: `crypto/ed25519` + `crypto/x509` (RFC-0002 X.509 builder) + `golang.org/x/crypto/pbkdf2` + `crypto/aes` GCM
- **Storage**: SQLite via `modernc.org/sqlite` (pure Go, no CGo)
