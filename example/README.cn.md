[English Version](./README.md) | 中文版

# NIP CA Server —— 参考实现

本目录收录 NIP CA Server 的 Python、TypeScript、Java、Rust、Go 五种额外实现。
它们作为 [NPS-3 §8](https://gitee.com/labacacia/nps/blob/main/spec/NPS-3-NIP.cn.md)
CA REST 接口的**参考移植**保留，方便你阅读或 fork 非 .NET 版本。

## 状态

| 项目 | 参考实现（本目录） | 发布参考实现（`..` / .NET） |
|------|--------------------|------------------------------|
| 维护 | 否 | 是 |
| 发布 | 否（无 Docker 镜像、无 Tag） | 是（`v1.0.0-alpha.3`+） |
| 规范同步 | 冻结在 `v1.0.0-alpha.2` | 与套件同步 |
| CI   | 不纳入 | 每次发布构建 + 测试 |
| 推荐用于生产 | 否 | 是 |

父目录的 .NET 实现是**唯一**会发布镜像和 SemVer Tag 的实现。
任何真实部署都用它。本目录的几个实现作为学习材料阅读。

## 目录

| 文件夹 | 技术栈 |
|--------|--------|
| [`python/`](./python/) | FastAPI + SQLite, Python 3.12 |
| [`ts/`](./ts/)         | Fastify + SQLite, Node.js + TypeScript |
| [`java/`](./java/)     | Spring Boot 3.4 + SQLite, Java 21 |
| [`rust/`](./rust/)     | Axum + SQLite, Rust stable |
| [`go/`](./go/)         | net/http stdlib + SQLite, Go 1.23 |

每个子目录都保留了冻结时刻的原始 README、Dockerfile 和源代码，
你可以本地 `docker compose up` 跑起来，但上游不再向其同步变更。

## 想接手某个实现

欢迎提 PR：

1. 把实现追到当前 `spec/NPS-3-NIP.md` 修订版。
2. 接入 .NET 实现使用的发布流水线（Dockerfile + CI 矩阵 + CHANGELOG +
   版本号同步到套件当前 `1.0.0-alpha.x`）。
3. 在本 README 把你列为该实现的维护者。

请先开 Issue 讨论路径，再投入时间动手。
