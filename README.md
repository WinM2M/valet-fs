# ValetFS Desktop Daemon (`valetfs`)

ValetFS is a Zero-Backend, P2P, in-memory virtual file system that exposes
short-lived tokens and keys to AI agents only while a paired mobile app
allows it.

This repository contains the Go implementation of the desktop daemon plus
a Cloudflare Worker signaling stub.

## Layout

```
valet-fs/
├── cmd/valetfs/       # main.go entry point
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
go build ./cmd/valetfs
```

On Linux you need the FUSE userspace headers (`libfuse-dev` or equivalent).

### FUSE auto-detection and always-on WebDAV

`valetfs` self-diagnoses whether a real FUSE mount is possible on the host
(checks `/dev/fuse`, its permissions, and that `fusermount` is on `PATH`).

* WebDAV is started by default and binds to an ephemeral loopback port
  (`--webdav-addr`, default `127.0.0.1:0`).
* FUSE is attempted in parallel. If unavailable, the daemon keeps running and
  exposes the failure state in `/status`.

The user does **not** need to install drivers, load kernel modules, or run
as root. Agents that cannot speak WebDAV can also reach files through the
Dev HTTP API described below.

## Run (daemon)

```sh
./valetfs serve --dev
```

`valetfs` always exposes a local control API on an ephemeral port
(`--dev-addr`, default `127.0.0.1:0`).

Control auth token behavior:

* If `VALETFS_CONTROL_TOKEN` is set, that token is used.
* Otherwise `valetfs` generates a random token.
* Startup logs include a tokenized control URL.
* Runtime metadata is written to `~/.valetfs/run/runtime.json` for CLI use.

Control API endpoints:

| Method | URL | Effect |
|--------|--------------------------|--------|
| POST   | `/mount`                 | Mount the VFS                  |
| POST   | `/unmount`               | Unmount the VFS                |
| POST   | `/sync`                  | Commit a manifest to the diff repo |
| GET    | `/status`                | Report mount + quota usage     |
| GET/POST/DELETE | `/files?path=/keys/x` | CRUD on a single file |
| GET | `/files?path=/keys&list=1` | List directory children |

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
./valetfs serve --signaling https://your-worker.workers.dev
```

The daemon prints an ASCII QR code; scan it from the ValetFS mobile app to
complete WebRTC pairing.

## Two-device Vault Pairing (CLI to CLI)

You can test vault-origin and remote serve pairing without mobile app.

Prerequisites:

* Both devices can access the same Cloudflare Worker signaling URL.
* Vault device has `VALETFS_VAULT_PASSWORD` set (or use `--password-file`).

Device A (remote target, run daemon):

```sh
valetfs serve --signaling https://valetfs-signaling.winm2m.workers.dev
```

The daemon prints `Session ID: <id>` in stdout.

Device B (vault origin/controller):

```sh
export VALETFS_VAULT_PASSWORD='change-me'
valetfs vault init
valetfs vault add ./my-key.pem fs:/keys/my-key.pem
valetfs vault pair <SESSION_ID> --signaling https://valetfs-signaling.winm2m.workers.dev
```

After pairing, the vault file is pushed to Device A memory FS via WebRTC DataChannel.

Optional follow-up commands:

```sh
valetfs vault sync <SESSION_ID> --signaling https://valetfs-signaling.winm2m.workers.dev
valetfs vault status <SESSION_ID> --signaling https://valetfs-signaling.winm2m.workers.dev
valetfs vault unmount <SESSION_ID> --signaling https://valetfs-signaling.winm2m.workers.dev
```

Note: current implementation is optimized for first controller pairing per session.
For repeated `status/sync/unmount`, create a fresh serve session if rejoin times out.

## Local CLI (separate process)

`valetfs` also supports local helper commands that connect to the running daemon
using the runtime metadata file, with a short 500ms timeout:

```sh
valetfs status
valetfs ls tmp
valetfs ls -la tmp
valetfs cat tmp/github
valetfs cp ./local.txt tmp/local.txt
valetfs cp tmp/local.txt ./out.txt
valetfs cp tmp/a tmp/b
valetfs mv tmp/local.txt tmp/local2.txt
valetfs rm tmp/local2.txt
valetfs mkdir -p tmp/nested/dir
valetfs rmdir tmp/emptydir
```

Path rules:

* If a path starts with `/`, `./`, or `../`, it is treated as a host path.
* If a path starts with `fs:`, it is always treated as an in-memory FS path.
* Otherwise it is treated as an in-memory FS path.
* `ls`, `cat`, `rm`, `mkdir`, and `rmdir` only accept FS paths and fail for host paths.
* `cp` and `mv` support `host -> fs`, `fs -> host`, and `fs -> fs`.

This allows explicit FS root addressing like:

```sh
valetfs cp ./hello.txt fs:/
```

Examples:

```sh
valetfs ls tmp
valetfs cp ./hello tmp/
valetfs rm tmp/hello
```

Recursive copy from host directory to FS is supported:

```sh
valetfs cp -r ./secrets tmp/
```

`rm` behavior:

* `valetfs rm <path>` removes files only.
* `valetfs rm -r <path>` removes directories recursively.

`rmdir` removes only empty directories.

`mkdir` supports `-p`.

`cp`/`mv` fail if destination already exists.

Shell completion (bash):

```sh
source <(valetfs completion bash)
```

Then press TAB for `ls`, `cat`, `rm`, `mkdir`, `rmdir`, `cp`, `mv` path suggestions. FS suggestions
use daemon API; host suggestions use local filesystem rules.

## Security guarantees enforced in code

* **Idempotent mount.** Every startup runs `fusermount -uz` (or
  `net use /delete` on Windows) before re-mounting (see
  `internal/vfs.PreUnmount`).
* **Graceful shutdown.** `SIGINT` / `SIGTERM` are trapped in
  `cmd/valetfs/main.go` and call `Daemon.Shutdown`, which unmounts then
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
