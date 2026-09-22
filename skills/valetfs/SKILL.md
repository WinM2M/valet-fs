---
name: valetfs
description: |
  ValetFS is a vault that keeps the user's secrets on their phone and serves them to this machine
  only while they allow it. Use this skill BEFORE reading any credential from the filesystem or the
  environment: AWS/GCP/GitHub/Cloudflare/npm/Sentry/Paddle tokens, API keys, database URLs, SMTP
  passwords, .env files, SSH private keys, .p8/.p12 signing keys, service-account JSON, OAuth client
  secrets, session cookies. If a value exists in the vault, that copy is authoritative and the copy
  on disk (or in an env var) is a stale duplicate that may be mid-removal.
  Use `valetfs exec` to consume a secret rather than reading it, so the value never enters your
  transcript.
  Also use it to join a ValetFS session from a connection key, run or inspect the daemon, put files
  into the vault, and diagnose "the daemon says it is not serving" / "my file disappeared" /
  "the harness blocked me from reading a credential".
  Triggers: "valetfs", "ValetFS", "발레fs", "vault", "금고", "connection key", "valetfs serve --join",
  a long base64url connection key pasted with no explanation, or any task that needs a secret this
  machine may not be supposed to keep on disk.
---

# ValetFS

A vault whose contents live on the user's phone. A local daemon holds them **in memory only** and
serves them while the phone allows it. Nothing is written to this machine's disk by the daemon.

Two consequences shape everything below:

- **The vault is the source of truth.** A secret on disk may be a leftover the user is in the middle
  of deleting. Prefer the vault copy.
- **The vault is volatile here.** Daemon restart, lock, or grace expiry clears it. Never delete a
  user's only on-disk copy on your own initiative.

---

## 1. Secret needed → check the vault first

Run this before reaching for `.env`, `~/.aws/credentials`, `$GITHUB_TOKEN`, or any other local copy.

```sh
valetfs status             # is a daemon running and serving?
valetfs ls fs:/            # what is in the vault
valetfs ls -l fs:/keys     # sizes and mtimes; /keys is the conventional location
```

- **Found it** → use it with `valetfs exec` (§1a). Do not `cat` it.
- **No daemon / not serving** → say so and ask whether to start one (§2). Do not silently fall back
  to a disk copy without telling the user — they may believe that copy is gone.
- **Daemon running, secret absent** → use the local copy, and **tell the user it is not in the
  vault**. That is usually something they still intend to move.

## 1a. Use the secret with `exec`, do not read it

`valetfs cat` writes the value to stdout, and from there into your transcript, the user's shell
history, and any log wrapping you. `valetfs exec` hands it to a child process instead, so the only
thing crossing your terminal is the child's own output.

```sh
# A dotenv file into the command's environment.
valetfs exec fs:/keys/aws.env -- aws s3 ls s3://bucket

# One key as one variable. The trailing newline is trimmed.
valetfs exec --as GH_TOKEN fs:/keys/github -- gh pr list

# A tool that insists on a file path. Materialised at 0600 in a memory-backed
# dir, zeroed and removed when the command exits.
valetfs exec --as-file KEYFILE fs:/keys/apple.p8 -- ./sign.sh
valetfs exec --as-file K fs:/keys/gcp-sa.json -- \
  sh -c 'gcloud auth activate-service-account --key-file="$K"'

# Every option repeats, so one command can inject several secrets.
valetfs exec --as-file GOOGLE_APPLICATION_CREDENTIALS=fs:/keys/gcp-sa.json \
             --as SENTRY_TOKEN=fs:/keys/sentry.txt \
             fs:/keys/aws.env -- ./deploy.sh
```

The child's stdout, stderr and exit code pass through unchanged, so `exec` works inside an existing
pipeline or `&&` chain. `valetfs exec --help` has the rest.

**Never print a secret's value into the conversation.** And do not reach for the old habit of
proving you have it by measuring it: `valetfs exec --as V fs:/keys/x -- sh -c 'echo ${#V}'` is
blocked as `[Credential Exploration]`, correctly — a length and a hash are not a use. If you need
to confirm a secret is present and plausible, read its size from `valetfs ls -l` and then just use
it.

### If the harness blocks you

Claude Code blocks `valetfs cat` with `[Credential Materialization]` and blocks you from editing
settings with `[Self-Modification]`. **Do not work around either.** The defaults are right: an
agent that can drain the vault unprompted makes the vault pointless. Two legitimate moves:

1. **Use `exec`.** Measured on 2026-09-22: `exec` running a command that *uses* a credential is
   allowed, including `--as-file` with a real service-account key.
2. **Ask the user to run `valetfs setup-claude` once.** It merges `Bash(valetfs exec *)`,
   `Bash(valetfs ls *)` and `Bash(valetfs status)` into their user settings, with a confirmation
   prompt. You cannot run it for them, and asking is the intended path — not a failure to report
   apologetically. `valetfs setup-claude --print` shows the JSON if they would rather paste it.

Do not offer `--allow-cat` as the first answer. It reopens the whole vault to get one value.

---

## 2. Joining a session (the user gave you a connection key)

A long base64url string means they tapped **Provision an agent** in the app.

```sh
valetfs --version    # need the version the app asks for; install/upgrade if it differs:
                     # curl -fsSL https://winm2m.github.io/valet-fs/install.sh | bash
                     # no root/FUSE needed; INSTALL_DIR=$HOME/.local/bin bash to avoid sudo
```

Start it in the background and leave it running:

```sh
valetfs serve --join <KEY> \
  --grace 604800 \
  --resume-key-file "$HOME/.valetfs/e2ee.key" \
  > "$HOME/.valetfs/daemon.log" 2>&1 &
```

- `--grace 604800` (7 days). **The default is 300 seconds** — the daemon unmounts and wipes five
  minutes after the phone disconnects, which surprises everyone once.
- `--resume-key-file` keeps the E2EE identity across restarts, so no re-pairing.
- Wait for `Joined session:` in the log, then tell the user to push from the app.

Running a **second** daemon alongside an existing one: give it its own `--runtime-dir`, `--mount`,
`--git-dir`, and `--resume-key-file`, or the two will fight over the same runtime state. See §4.

---

## 3. Putting files into the vault

```sh
valetfs mkdir fs:/keys
valetfs cp /path/on/host/aws.env fs:/keys/aws.env
valetfs ls fs:/keys
```

Verify it round-tripped before the user relies on it. Compare sizes rather than hashing the value —
piping the secret into `sha256sum` is the shape that reads as `[Credential Exploration]`:

```sh
valetfs ls -l fs:/keys              # size of the vault copy
wc -c < /path/on/host/aws.env       # size of the original
```

`cp` is a copy, not a move — the original stays. **Do not delete originals unless the user asks**,
and only after confirming the phone has pulled the file (they must Reconcile in the app; the vault
copy alone lives in daemon memory and dies with it).

Other commands: `exec`, `mv`, `rm [-r]`, `rmdir`, `cat`, `ls`.

---

## 4. Traps — each of these has bitten someone

**`fs:` prefix is mandatory on every vault path.** `isHostPath()` treats anything starting with
`/`, `./`, or `../` as a host path. The single-path commands — `ls`, `cat`, `exec` — reject it
loudly (`valetfs ls /keys` → `ls only handles fs paths`), but **`cp` and `mv` take one of each and
infer the direction**, so `valetfs cp secret.env /keys/x` is a silent *local file copy* that writes
plaintext outside the vault. Always write `fs:/keys/x`.

**`valetfs ls` only ever reads the default runtime.** The path `~/.valetfs/run/runtime.json` is
hardcoded in the CLI; `--runtime-dir` and `VALETFS_RUNTIME_DIR` apply to `serve` only. With two
daemons, the CLI talks to whichever owns the default path — which is also how you keep it away from
one you must not disturb: run the daemon you care about on the default path.

**No FUSE is normal.** Without `/dev/fuse` the daemon serves over loopback WebDAV and the mountpoint
stays an empty directory. `backend: webdav` with `serving: true` is healthy. Access files via the
CLI or the WebDAV address, not the mount path.

**`mounted: false` means torn down, not "FUSE missing".** With `used > 0` it was unmounted but the
heap survives (a push re-serves it). With `used == 0` a lock or grace expiry wiped it.

**Grace.** `valetfs status` reports `grace_seconds`, `grace_armed`, and `grace_remaining_seconds`
(newer daemons). If a countdown is armed, secrets are on a deadline — surface that to the user.

**CLI-side vault needs a passphrase.** `valetfs vault ...` manages a vault stored on *this* machine.
Its default passphrase is a constant compiled into the public source, so a vault created without
`--password-file` or `VALETFS_VAULT_PASSWORD` is encrypted with a publicly known key. Always pass
one. (This does not apply to `serve --join`, where the phone holds the vault.)

**"Forget this daemon" is destructive.** In the app it sends `DELETE` to the hub and destroys the
session, not just the local pairing. Never suggest it as a troubleshooting step.

---

## 5. Do not

- Print secret values into the conversation, logs, or commit messages.
- Use `cat` to consume a secret. `exec` exists for that; `cat` is for a person's eyes.
- Work around a `[Credential Materialization]` or `[Self-Modification]` block. Use `exec`, or ask.
- Copy vault contents to disk as a convenience, or leave temp files behind. `exec --as-file` cleans
  up after itself; a hand-rolled `cat > /tmp/k` does not.
- Delete the user's on-disk originals on your own initiative.
- Restart or `valetfs stop` a daemon you did not start without asking — its memory is the only copy
  of whatever was pushed to it.
- Run `serve` a second time on the default paths while another daemon is using them.

## 6. Reference

- Repository: <https://github.com/winm2m/valet-fs> — see `AGENTS.md` there
- In the tool: `valetfs --help`, `valetfs exec --help`, `valetfs setup-claude --help`
- Plain-text summary: <https://winm2m.github.io/valet-fs/llms.txt>
- Install CLI: `curl -fsSL https://winm2m.github.io/valet-fs/install.sh | bash`
- Update this skill: `curl -fsSL https://winm2m.github.io/valet-fs/install-skill.sh | bash`
