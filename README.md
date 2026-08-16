English | [中文版](./README.cn.md)

# NIP CA Server

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](../../LICENSE)
[![NuGet](https://img.shields.io/nuget/v/LabAcacia.NPS.NIP.svg?label=LabAcacia.NPS.NIP)](https://www.nuget.org/packages/LabAcacia.NPS.NIP/)
[![GitHub Release](https://img.shields.io/github/v/release/labacacia/nip-ca-server?include_prereleases)](https://github.com/labacacia/nip-ca-server/releases)
[![Release](https://img.shields.io/badge/release-v1.0.0--alpha.18-orange.svg)](CHANGELOG.md)
[![NIP](https://img.shields.io/badge/NIP-v0.14-7b61ff.svg)]()
[![Spec](https://img.shields.io/badge/spec-NPS--3%20%C2%A78-success)](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.md)

Self-hostable Certificate Authority for the **Neural Identity Protocol**
(NPS-3) — a single-binary ASP.NET Core service that issues, renews and
revokes Ed25519 NID certificates for NPS Agents and Nodes.

This is the **reference release implementation**. Five additional ports
(Python, TypeScript, Java, Rust, Go) live under [`example/`](./example/)
as unmaintained reference reads.

> Source of truth: [github.com/labacacia/nip-ca-server](https://github.com/labacacia/nip-ca-server) ·
> Mirror: [gitee.com/labacacia/nip-ca-server](https://gitee.com/labacacia/nip-ca-server) ·
> Spec: [NPS-3 NIP §8](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.md) ·
> Suite: [NPS-Release](https://github.com/labacacia/NPS-Release)

---

## Features

- **NID issuance** for Agents and Nodes per [NPS-3 §8](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.md)
- **Ed25519** signing throughout
- **AES-256-GCM + PBKDF2** at-rest encryption for the CA private key
- **PostgreSQL** storage (Docker Compose ships a Postgres 16 sidecar); **SQLite** available for embedded / single-binary use via `AddNipCaWithSqlite()`
- **OCSP** + **CRL** + **`/.well-known/nps-ca`** discovery
- **Single Docker image**, non-root, healthcheck baked in
- **Operator auth** — optional Bearer token guards all write endpoints
- **ACME** — optional RFC 8555 + NPS-RFC-0002 `agent-01` challenge (set `NIPCA__ACMEENABLED=true`)

## Quick Start

The fastest path is the bundled `docker-compose.yml`:

```bash
git clone https://github.com/labacacia/nip-ca-server.git
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

Then point your NPS Agents and Nodes at `https://ca.example.com` for
registration and renewal.

## Configuration

All secrets MUST come from environment variables. Non-secret defaults
are in `appsettings.Docker.json`.

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `NIPCA__CANID` | yes | — | CA NID, e.g. `urn:nps:org:ca.example.com` |
| `NIPCA__KEYPASSPHRASE` | yes | — | Passphrase for the encrypted CA key file |
| `NIPCA__BASEURL` | yes | — | Public HTTPS base URL of this CA |
| `CONNECTIONSTRINGS__POSTGRES` | yes | — | Postgres connection string |
| `NIPCA__DISPLAYNAME` | no | `NPS CA` | Human-readable CA name |
| `NIPCA__KEYFILEPATH` | no | `/data/ca.key.enc` | Encrypted CA key file path |
| `NIPCA__AGENTCERTVALIDITYDAYS` | no | `30` | Agent certificate validity window |
| `NIPCA__NODECERTVALIDITYDAYS` | no | `90` | Node certificate validity window |
| `NIPCA__RENEWALWINDOWDAYS` | no | `7` | Days before expiry that renewal opens |
| `NIPCA__NORMALIZEOCSPRESPONSETIME` | no | `true` | Round OCSP `producedAt` to the second |
| `NIPCA__OPERATORAPIKEY` | no | — | Bearer token required on all write endpoints; omit to disable auth (dev only) |
| `NIPCA__METRICSBEARERTOKEN` | no | `NIPCA__OPERATORAPIKEY` | Bearer token for `/metrics`; when neither token is configured, `/metrics` returns 404 while `/healthz` and `/readyz` remain public |
| `NIPCA__ALLOWEDCAPABILITIES` | no | — | Comma-separated capability allowlist; requests with unlisted caps are rejected with 403 |
| `NIPCA__ACMEENABLED` | no | `false` | Enable ACME RFC 8555 + `agent-01` challenge (NPS-RFC-0002) |
| `NIPCA__ACMEPATHPREFIX` | no | `/acme` | HTTP route prefix for ACME endpoints |

### TLS

The container exposes plain HTTP on `17435`. Run it behind nginx, Caddy
or Traefik for TLS termination — your `BASEURL` must point at the
public HTTPS endpoint.

## API Surface

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/v1/agents/register` | Register Agent, issue `IdentFrame` (Ed25519) |
| `POST` | `/v1/agents/register-x509` | Register Agent, issue dual-trust frame (Ed25519 + X.509 chain, NPS-RFC-0002) |
| `POST` | `/v1/agents/{nid}/renew` | Renew Agent certificate |
| `POST` | `/v1/agents/{nid}/revoke` | Revoke Agent certificate |
| `GET`  | `/v1/agents/{nid}/verify` | Verify / OCSP for an Agent NID |
| `POST` | `/v1/nodes/register` | Register Node, issue `IdentFrame` (Ed25519) |
| `POST` | `/v1/nodes/register-x509` | Register Node, issue dual-trust frame (Ed25519 + X.509 chain, NPS-RFC-0002) |
| `POST` | `/v1/nodes/{nid}/renew` | Renew Node certificate |
| `POST` | `/v1/nodes/{nid}/revoke` | Revoke Node certificate |
| `GET`  | `/v1/nodes/{nid}/verify` | Verify / OCSP for a Node NID |
| `POST` | `/v1/orchestrators/groups/register` | Register orchestrator group NID (NPS-CR-0003) |
| `POST` | `/v1/orchestrators/groups/{group_nid}/sessions/issue` | Issue short-lived session NID under a group (NPS-CR-0003) |
| `POST` | `/v1/orchestrators/groups/{group_nid}/revoke` | Revoke a group + cascade-revoke its live sessions (NPS-CR-0003) |
| `GET`  | `/v1/orchestrators/groups/{group_nid}/sessions` | List sessions under a group (audit, NPS-CR-0003) |
| `GET`  | `/v1/ca/cert` | CA public key |
| `GET`  | `/v1/crl` | Certificate Revocation List |
| `GET`  | `/.well-known/nps-ca` | CA discovery document |
| `GET`  | `/health` | Health check (returns 200 when ready) |

Write endpoints (`register`, `register-x509`, `renew`, `revoke`, `orchestrators/groups/...`) require `Authorization: Bearer <token>` when `NIPCA__OPERATORAPIKEY` is set.

`/metrics` is not public. Set `NIPCA__METRICSBEARERTOKEN` for a monitoring-plane credential, or let it reuse `NIPCA__OPERATORAPIKEY`. If neither is set, `/metrics` returns 404 instead of exposing operational counters.

The `sessions/issue` endpoint additionally accepts an Ed25519 group-JWS body (`Content-Type: application/jose+json`, header `alg=EdDSA, kid=<group_nid>, nps-purpose=session-issue`) so an orchestrator that holds the group's private key can self-issue sessions without an Operator credential. See [NPS-3 §5.1.3 / §8](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.md) and [NPS-CR-0003](https://github.com/labacacia/NPS-Release/blob/main/spec/cr/NPS-CR-0003-orchestrator-group-session-nids.md).

Field-level shapes are defined in [NPS-3 §8](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.md).

## Build from source

```bash
dotnet restore
dotnet build -c Release
dotnet run --project NPS.NipCaServer.csproj
```

The .NET 10 SDK is required. Dependency `LabAcacia.NPS.NIP` is pulled
from nuget.org.

## Docker image

**No pre-built image is published.** NPS ships the protocol suite and its
components as source and language packages; container images are not part of
the release. Build the image yourself from this repository:

```bash
docker build -t nip-ca-server:1.0.0-alpha.18 .
```

Or bring it up together with its dependencies:

```bash
docker compose up -d --build
```

## Versioning

This repo follows the umbrella SemVer of the NPS suite. While NPS is
pre-1.0, every component repo carries the same `1.0.0-alpha.x` tag.
See [`CHANGELOG.md`](./CHANGELOG.md) for per-version notes.

## Relationship to the rest of NPS

| Role | Where |
|------|-------|
| Spec — NIP protocol | [`NPS-Release/spec/NPS-3-NIP.md`](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.md) |
| .NET NIP client SDK | [`labacacia/NPS-sdk-dotnet`](https://github.com/labacacia/NPS-sdk-dotnet) |
| Other-language NIP SDKs | [`labacacia/NPS-sdk-{py,ts,java,rust,go}`](https://github.com/orgs/labacacia/repositories?q=NPS-sdk) |
| Suite umbrella | [`labacacia/NPS-Release`](https://github.com/labacacia/NPS-Release) |
| Development monorepo | private — releases land here as one-way syncs |

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

Copyright © 2026 LabAcacia (INNO LOTUS PTY LTD).

## Contributing

Issues and pull requests are welcome. Please open an issue first for any
non-trivial change so we can confirm scope before you spend time. The
`example/` ports are frozen — see [`example/README.md`](./example/README.md)
for the path to revive one.
