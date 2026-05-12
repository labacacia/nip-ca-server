English | [中文版](./README.cn.md)

# NIP CA Server — Rust

Axum + SQLite implementation of the NIP Certificate Authority (NPS-3 §8).

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
| `NIP_CA_ROOT_CERT_FILE` | No | `/data/ca.root.der` | RFC-0002 self-signed X.509 root cert (re-issued on every boot from the CA key, 5-year validity, written here for external observability) |
| `PORT` | No | `17440` | |

> **Root cert lifecycle (Rust-specific):** Unlike the other CA Server reference ports, this implementation re-issues a fresh self-signed root cert on every boot (same Ed25519 key, new `notBefore`/`notAfter`). The DER at `NIP_CA_ROOT_CERT_FILE` changes on each restart — **do not byte-pin it**. Pin the CA's Ed25519 public key instead, or fetch the cert from `/.well-known/nps-ca` after each restart.

## API

Same endpoints as all other NIP CA Server implementations — see [NPS-3 §8](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.md).

`alpha.4` adds two `v2` endpoints per **NPS-RFC-0002** that issue dual-trust IdentFrames carrying both the v1 Ed25519 signature **and** a 2-cert X.509 chain (leaf + self-signed root):

| Method | Path | Description |
|--------|------|-------------|
| **POST** | **`/v2/agents/register`** | NPS-RFC-0002 — issue dual-trust v2 IdentFrame |
| **POST** | **`/v2/nodes/register`** | NPS-RFC-0002 — same shape for node-role NIDs |

`/.well-known/nps-ca` advertises `cert_formats: ["v1-proprietary", "v2-x509"]` and the new `register_v2` endpoint URL; schema bumped to `nps_ca: "0.2"`.

ACME `agent-01` server endpoints on the axum app are not exposed in alpha.4 (matches `tools/nip-ca-server/` C# parity); the SDK's `nps_nip::acme::AcmeServer` is the canonical reference for ACME and can be embedded in production deployments separately.

## Local Development

```bash
NIP_CA_NID=urn:nps:org:ca.local \
  NIP_CA_PASSPHRASE=dev-pass \
  NIP_CA_BASE_URL=http://localhost:17440 \
  cargo run
```

## Stack

- **Runtime**: Rust stable
- **Framework**: Axum 0.8 + Tokio
- **Crypto**: ed25519-dalek 2 + aes-gcm + pbkdf2 + sha2 + **rcgen 0.13** (RFC-0002 X.509 builder)
- **Storage**: SQLite via rusqlite (bundled)
