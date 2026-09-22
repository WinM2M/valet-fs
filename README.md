# ValetFS — keep API keys on your phone, not in a dotfile

Your API keys stay on your phone, behind Face ID. When a tool or an AI agent on
your computer needs one, the `valetfs` daemon borrows it — into memory, never
onto disk — and gives it back when the work is done. Close the app and a grace
timer starts; when it expires the daemon unmounts and wipes itself.

Nothing is left in a dotfile, an environment variable or a config directory for
the next prompt injection to find.

```sh
valetfs serve                                 # prints a QR code — scan it with the app
valetfs exec fs:/keys/aws.env -- aws s3 ls    # use a secret without ever reading it
```

**Why this exists.** Workload identity federation removed static keys from
workloads that run inside a cloud, because those already have an identity to
exchange for a short-lived token. A laptop, a home server and the container an
agent runs in have none, so the practical advice for local agents is still
"export it in your shell profile". [Where workload identity federation can't
go](https://winm2m.github.io/valet-fs/federated-identity-gap.html) sets out the
gap and, just as plainly, what this does not fix.

Technically: a zero-backend, peer-to-peer, in-memory virtual file system that
exposes short-lived tokens and keys to AI agents only while a paired mobile app
allows it. This repository holds the Go daemon and a Cloudflare Worker signaling
stub. MIT licensed; the iOS app is optional and sells convenience, not access.

## Using ValetFS from an AI agent

**AI agents: read this first.** Full guidance is in [AGENTS.md](AGENTS.md), and
a plain-text summary for model context is at
<https://winm2m.github.io/valet-fs/llms.txt>.

Never read a secret in order to use it. `valetfs cat` writes the value to
stdout, and from there into an agent's transcript, the shell history, and any
log wrapping it. Use `valetfs exec`, which hands the value to a child process
instead:

```sh
valetfs exec fs:/keys/aws.env -- aws s3 ls s3://bucket
valetfs exec --as EL_KEY fs:/keys/elevenlabs/api-key.txt -- node tts.mjs
valetfs exec --as-file KEYFILE fs:/keys/apple.p8 -- ./sign.sh
```

The child's stdout, stderr and exit code pass through unchanged, so `exec` drops
into an existing pipeline or `&&` chain. `--as-file` materialises into a
memory-backed directory at mode 0600 and zeroes and removes it on exit. Every
option repeats, so one command can inject several secrets. See
`valetfs exec --help`.

`valetfs ls` and `valetfs status` are safe to call: they report names, sizes and
daemon state, never contents. `valetfs cat` stays for the case it is actually
for — a person reading a value with their own eyes.

`exec` is not a way around a permission check; it still needs read access to the
vault. What changes is the blast radius. Allowing `cat` opens the whole vault,
while `exec` grants one command's use of one secret.

### If your agent harness blocks the vault

Claude Code's classifier blocks `valetfs cat` with `[Credential
Materialization]`, and blocks an agent from editing its own settings with
`[Self-Modification]`. **Both defaults are correct**: an agent that can drain a
vault on its own initiative defeats the point of having one. So the way through
is not a workaround — it is a person running one command:

```sh
valetfs setup-claude            # merge the rules, with a confirmation prompt
valetfs setup-claude --print    # just show the JSON; write nothing
```

That merges the following into the user-scope settings file
(`$CLAUDE_CONFIG_DIR/settings.json` if set, otherwise `~/.claude/settings.json`
— user scope, because a vault belongs to a machine rather than a repository).
Every other key and its order is preserved, the previous file is kept as
`settings.json.valetfs-backup`, and running it twice does nothing:

```json
"permissions": {
  "allow": [
    "Bash(valetfs exec *)",
    "Bash(valetfs ls *)",
    "Bash(valetfs status)"
  ]
}
```

Write and delete (`cp`, `mv`, `rm`) are deliberately absent: emptying a vault
should take a confirmation. So is `cat`; add it with `--allow-cat` if you have a
tool that cannot be driven through `exec`.

Measured on Claude Code in auto mode (2026-09-22):

| Command shape | Result |
| :--- | :--- |
| `valetfs status`, `valetfs ls` | allowed |
| `valetfs cat fs:/keys/…` | blocked, `[Credential Materialization]` |
| `valetfs exec --as-file K fs:/keys/gcp/sa.json -- gcloud auth activate-service-account --key-file=$K` | allowed, with a real key |
| `valetfs exec fs:/keys/aws.env -- <command that uses it>` | allowed |
| `valetfs exec --as V fs:/keys/… -- sh -c 'echo ${#V}'` | blocked, `[Credential Exploration]` |

The last row is the useful subtlety: the classifier judges the *child command*,
not the `exec` verb. Using a credential passes; measuring one does not — which
is a fair reading, since a length and a hash are not a use. To confirm a secret
is present, read its size from `valetfs ls -l` and then just use it.

## AI agent quickstart — join a session from the ValetFS app

If a user asks you (an AI agent / coding assistant) to connect to their ValetFS
session, they will have tapped **"Provision an agent"** in the ValetFS mobile
app and given you a **connection key** (a long base64url string). To receive
their secrets into an in-memory vault on this machine, do exactly two steps:

**1. Install the `valetfs` CLI** (Linux x86_64 / arm64):

```sh
curl -fsSL https://winm2m.github.io/valet-fs/install.sh | bash
```

No root, drivers, or FUSE are required — if FUSE is unavailable the daemon
serves files over a loopback WebDAV endpoint and the local CLI instead. To
install without sudo: `... | INSTALL_DIR=$HOME/.local/bin bash` (and ensure that
dir is on `PATH`). On macOS/Windows or unsupported arches, build from source:
`git clone https://github.com/winm2m/valet-fs && cd valet-fs && go build -o valetfs ./cmd/valetfs`.

**1b. Install the agent skill** (Claude Code and other skill-capable agents):

```sh
curl -fsSL https://winm2m.github.io/valet-fs/install-skill.sh | bash
```

This drops a `valetfs` skill into `~/.claude/skills/`, so the agent keeps
checking the vault before reading credentials off disk in *later* sessions too —
not just the conversation where the key was pasted. Set `SKILL_DIR=` to install
into one project instead. Skip if your tool has no skill mechanism.

**2. Join the session** with the key the user gave you:

```sh
valetfs serve --join <CONNECTION_KEY>
```

This connects to the app-provisioned session as the daemon, publishes an E2EE
public key, and starts an **in-memory** file system. Leave it running (e.g. in a
background process). Once the user pushes secrets from the app, read them with
the local CLI (separate terminal / process):

```sh
valetfs ls -l fs:/keys        # list what the app pushed, with sizes
valetfs status                # mount state, bytes used, grace countdown

# Use a secret without reading it (preferred — see the section above):
valetfs exec fs:/keys/aws.env -- aws s3 ls s3://bucket
valetfs exec --as GH_TOKEN fs:/keys/github -- gh pr list

valetfs cat fs:/keys/github   # print the value; for a person, not an agent
```

Vault paths need the `fs:` prefix — a bare `/keys` is read as a path on *this*
machine. `ls`/`cat`/`exec` reject that outright, but `cp`/`mv` accept both kinds
and infer the direction, so omitting it there silently writes plaintext to disk.

Notes for agents:

- The key is a **secret** (a bearer capability for this session) — do not log it,
  echo it into shared transcripts, or commit it.
- Secrets live only in the daemon's heap. On `Ctrl-C`, remote **Lock/Unmount**,
  or if the app **forgets** the session, the daemon unmounts and zero-wipes
  memory; if it sits unclaimed it auto-locks after the grace window.
- The connection key already contains the signaling URL, so `--signaling` is not
  needed. If the daemon prints `Joined session: <id>`, you are connected and can
  wait for the app to push.

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
├── skills/valetfs/    # SKILL.md for Claude Code and other skill-capable agents
├── docs/              # GitHub Pages site, incl. llms.txt for model context
├── AGENTS.md          # what an AI agent needs to know before touching the vault
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
./valetfs serve
```

The default transport is **`ws`** (WebSocket session hub / Cloudflare Durable
Object) with end-to-end encryption: `serve` prints a pairing QR encoding
`{v,sid,signaling,pub}`, and the hub/DO only ever relays ciphertext. Use
`--transport webrtc` (or `VALETFS_TRANSPORT=webrtc`) for the legacy P2P path.

If `--signaling` is omitted, default signaling URL is:

`https://valetfs-signaling.winm2m.workers.dev`

### TURN credential security model

`valetfs` does not embed TURN master keys in source or binaries.

Cloudflare Worker issues short-lived TURN credentials through
`GET /sessions/:id/turn` using Worker secrets:

* `TURN_DOMAIN`
* `TURN_SECRET`

Set them via Wrangler (never commit plain keys):

```sh
cd signaling
wrangler secret put TURN_DOMAIN
wrangler secret put TURN_SECRET
wrangler deploy
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
valetfs vault pair <SESSION_ID>
```

If `--signaling` is omitted in vault commands, the same default URL above is used.

After pairing, the vault file is pushed to Device A memory FS via WebRTC DataChannel.

Optional follow-up commands:

```sh
valetfs vault sync <SESSION_ID> --signaling https://valetfs-signaling.winm2m.workers.dev
valetfs vault status <SESSION_ID> --signaling https://valetfs-signaling.winm2m.workers.dev
valetfs vault unmount <SESSION_ID> --signaling https://valetfs-signaling.winm2m.workers.dev
```

Note: current implementation is optimized for first controller pairing per session.
For repeated `status/sync/unmount`, create a fresh serve session if rejoin times out.

### Verbose connection logs

To inspect where pairing fails, enable verbose mode on both sides:

```sh
valetfs serve -v
valetfs vault -v pair <SESSION_ID>
```

`-v` (or `--verbose`) prints detailed signaling/claim/answer/candidate exchange logs.

## Local CLI (separate process)

`valetfs` also supports local helper commands that connect to the running daemon
using the runtime metadata file, with a short 500ms timeout:

```sh
valetfs status
valetfs ls tmp
valetfs ls -la tmp
valetfs exec tmp/aws.env -- aws s3 ls
valetfs exec --as TOKEN tmp/github -- gh pr list
valetfs exec --as-file KEY tmp/apple.p8 -- ./sign.sh
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
* `ls`, `cat`, `exec`, `rm`, `mkdir`, and `rmdir` only accept FS paths and fail for host paths.
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

Then press TAB for `ls`, `cat`, `exec`, `rm`, `mkdir`, `rmdir`, `cp`, `mv` path suggestions. FS
suggestions use daemon API; host suggestions use local filesystem rules. For `exec`, suggestions
stop at the `--`: past that the words belong to the child command.

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
* **`exec` never writes a value to its own output.** Secrets reach the child
  process through its environment, and failures report the vault path and, for a
  malformed env file, a line number — never file content (see
  `cmd/valetfs/exec.go` and its tests). `--as-file` materialises at mode 0600 in
  a memory-backed directory when one exists, then zeroes and unlinks on every
  exit path, including signal death.

## Tests

```sh
go test ./...
```

The `internal/vfs` and `internal/sync` packages have headless unit tests
covering memory wiping, quota enforcement, path-traversal rejection, and
manifest non-leakage.
