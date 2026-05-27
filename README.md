# ValetFS Desktop Daemon (`valetd`)

ValetFS is a Zero-Backend, P2P, in-memory virtual file system that exposes
short-lived tokens and keys to AI agents only while a paired mobile app
allows it.

This repository contains the Go implementation of the desktop daemon plus
a Cloudflare Worker signaling stub.

## Layout

```
valet-fs/
├── cmd/valetd/        # main.go entry point
├── internal/
│   ├── config/        # CLI + .env parsing
│   ├── vfs/           # in-memory file system + FUSE/WebDAV mounters
│   ├── sync/          # go-git diff manifest repository
│   ├── webrtc/        # pion peer + Cloudflare bootstrap
│   └── daemon/        # lifecycle + dev HTTP control API
├── signaling/         # Cloudflare Worker (TypeScript)
├── .env.example
├── go.mod
└── README.md
```

## Build

```sh
go mod tidy
go build ./cmd/valetd
```

On Linux you need the FUSE userspace headers (`libfuse-dev` or equivalent).

### FUSE auto-detection and WebDAV fallback

`valetd` self-diagnoses whether a real FUSE mount is possible on the host
(checks `/dev/fuse`, its permissions, and that `fusermount` is on `PATH`).

* If FUSE is usable, it mounts the in-memory VFS at `--mount`.
* If not, it transparently runs `modprobe fuse` (and `sudo -n modprobe fuse`
  if available) once. If that still doesn't unblock FUSE - common inside
  containers - it falls back to an in-process WebDAV server bound to a free
  loopback port. The daemon logs the exact URL, e.g.
  `WebDAV fallback ready at http://127.0.0.1:35895/`.

The user does **not** need to install drivers, load kernel modules, or run
as root. Agents that cannot speak WebDAV can also reach files through the
Dev HTTP API described below.

## Run (Phase 1 dev mode)

```sh
./valetd --dev
```

Dev mode skips WebRTC entirely and exposes a local control API:

| Method | URL | Effect |
|--------|--------------------------|--------|
| POST   | `/mount`                 | Mount the VFS                  |
| POST   | `/unmount`               | Unmount the VFS                |
| POST   | `/sync`                  | Commit a manifest to the diff repo |
| GET    | `/status`                | Report mount + quota usage     |
| GET/POST/DELETE | `/files?path=/keys/x` | CRUD on a single file |

Example:

```sh
curl -X POST http://127.0.0.1:8080/files?path=/keys/github \
  -H 'content-type: application/json' \
  -d '{"content":"ghp_demo"}'
curl http://127.0.0.1:8080/files?path=/keys/github
curl -X POST http://127.0.0.1:8080/sync
```

## Run (production)

```sh
./valetd --signaling https://your-worker.workers.dev
```

The daemon prints an ASCII QR code; scan it from the ValetFS mobile app to
complete WebRTC pairing. Once the DataChannel is open the VFS auto-mounts.

## Security guarantees enforced in code

* **Idempotent mount.** Every startup runs `fusermount -uz` (or
  `net use /delete` on Windows) before re-mounting (see
  `internal/vfs.PreUnmount`).
* **Graceful shutdown.** `SIGINT` / `SIGTERM` are trapped in
  `cmd/valetd/main.go` and call `Daemon.Shutdown`, which unmounts then
  calls `MemFS.Wipe` to zero every file body before drop.
* **No plaintext on disk.** The diff repository at `$VALETFS_GIT_DIR`
  contains only `sha256 size /path` manifest lines, never token bodies
  (see `internal/sync/git.go` and its tests).
* **Quota enforcement.** `MemFS` rejects writes that would exceed the
  configured cluster quota (`--quota-mb`, default 5MB).

## Tests

```sh
go test ./...
```

The `internal/vfs` and `internal/sync` packages have headless unit tests
covering memory wiping, quota enforcement, path-traversal rejection, and
manifest non-leakage.
