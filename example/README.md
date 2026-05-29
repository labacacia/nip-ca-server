English | [中文版](./README.cn.md)

# NIP CA Server — Reference Implementations

This directory contains five additional NIP CA Server implementations in
Python, TypeScript, Java, Rust and Go. They are kept here as **reference
ports** of the [NPS-3 §8](https://github.com/labacacia/NPS-Release/blob/main/spec/NPS-3-NIP.md)
CA REST surface, useful when you want to read or fork a non-.NET version.

## Status

| Aspect | Reference impls (this folder) | Reference release impl (`..` / .NET) |
|--------|-------------------------------|--------------------------------------|
| Maintained | No | Yes |
| Released   | No (no Docker images, no tags) | Yes (`v1.0.0-alpha.11`+) |
| Spec parity | Frozen at `v1.0.0-alpha.11` | Tracks the suite |
| CI         | Excluded | Built + tested per release |
| Recommended for production | No | Yes |

The .NET implementation at the parent directory is the **only**
implementation we publish images and SemVer tags for. Use it for any
real deployment. The folders here are educational reads.

## Contents

| Folder | Stack |
|--------|-------|
| [`python/`](./python/) | FastAPI + SQLite, Python 3.12 |
| [`ts/`](./ts/)         | Fastify + SQLite, Node.js + TypeScript |
| [`java/`](./java/)     | Spring Boot 3.4 + SQLite, Java 21 |
| [`rust/`](./rust/)     | Axum + SQLite, Rust stable |
| [`go/`](./go/)         | net/http stdlib + SQLite, Go 1.23 |

Each folder keeps its original README, Dockerfile and source tree at
the time of the freeze, so you can `docker compose up` them locally,
but no upstream changes are flowing in.

## If you want to revive one

We are happy to accept a PR that:

1. Brings the impl up to the current `spec/NPS-3-NIP.md` revision.
2. Wires it into the release pipeline used by the .NET impl
   (Dockerfile + CI matrix + CHANGELOG + version bumped to the suite's
   current `1.0.0-alpha.x`).
3. Lists you as the maintainer in this README.

Open an issue first so we can talk about the path before you spend
time on it.
