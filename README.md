# publish-overlay

Files in this directory **replace** the equivalent root-level files of
`tools/nip-ca-server/` when syncing to the public release repo
[`labacacia/nip-ca-server`](https://github.com/labacacia/nip-ca-server).

The dev tree keeps the monorepo-aware variants at the root (e.g. a
`.csproj` with `<ProjectReference>` to `impl/dotnet/src/NPS.NIP/`) so
day-to-day development against in-tree NPS.NIP changes works without a
NuGet round-trip. The publish repo, on the other hand, must be
self-contained — it depends on the published `LabAcacia.NPS.NIP` NuGet
package and its Dockerfile / docker-compose context is the repo root,
not the monorepo root.

The sync script (`tools/release/sync-nip-ca-server.sh`) does:

1. `rsync` `tools/nip-ca-server/` → publish repo working tree.
2. Overlay each file under `publish-overlay/` onto the same relative
   path in the publish repo working tree (overwriting).
3. `rm -rf publish-overlay/` from the publish repo working tree.

Add a file here whenever the publish version of a file diverges from
the monorepo version. Keep this directory **small** — every file added
is one more thing to keep in sync by hand.
