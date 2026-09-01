---
name: valetfs
description: |
  ValetFS is a vault that keeps the user's secrets on their phone and serves them to this machine
  only while they allow it. Use this skill BEFORE reading any credential from the filesystem or the
  environment: AWS/GCP/GitHub/Cloudflare/npm/Sentry/Paddle tokens, API keys, database URLs, SMTP
  passwords, .env files, SSH private keys, .p8/.p12 signing keys, service-account JSON, OAuth client
  secrets, session cookies. If a value exists in the vault, that copy is authoritative and the copy
  on disk (or in an env var) is a stale duplicate that may be mid-removal.
  Also use it to join a ValetFS session from a connection key, run or inspect the daemon, put files
  into the vault, and diagnose "the daemon says it is not serving" / "my file disappeared".
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

- **Found it** → use the vault copy. `valetfs cat fs:/keys/aws.env`
- **No daemon / not serving** → say so and ask whether to start one (§2). Do not silently fall back
  to a disk copy without telling the user — they may believe that copy is gone.
- **Daemon running, secret absent** → use the local copy, and **tell the user it is not in the
  vault**. That is usually something they still intend to move.

Consume without writing plaintext to disk:

```sh
set -a; . <(valetfs cat fs:/keys/aws.env); set +a       # env vars for this shell only
valetfs cat fs:/keys/gcp-sa.json | gcloud auth activate-service-account --key-file=-
```

If a tool insists on a real path, write to a private temp file, use it, then remove it:

```sh
umask 077; valetfs cat fs:/keys/apple.p8 > /tmp/k.p8
... use /tmp/k.p8 ...
shred -u /tmp/k.p8 2>/dev/null || rm -f /tmp/k.p8
```

**Never print a secret's value into the conversation.** Report length and a short hash instead:
`len=40 sha1=18556f`.

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

Verify it round-tripped before the user relies on it:

```sh
valetfs cat fs:/keys/aws.env | sha256sum
sha256sum /path/on/host/aws.env
```

`cp` is a copy, not a move — the original stays. **Do not delete originals unless the user asks**,
and only after confirming the phone has pulled the file (they must Reconcile in the app; the vault
copy alone lives in daemon memory and dies with it).

Other commands: `mv`, `rm [-r]`, `rmdir`, `cat`, `ls`.

---

## 4. Traps — each of these has bitten someone

**`fs:` prefix is mandatory on every vault path.** `isHostPath()` treats anything starting with
`/`, `./`, or `../` as a host path. The single-path commands reject it loudly —
`valetfs ls /keys` → `ls only handles fs paths` — but **`cp` and `mv` take one of each and infer the
direction**, so `valetfs cp secret.env /keys/x` is a silent *local file copy* that writes plaintext
outside the vault. Always write `fs:/keys/x`.

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
- Copy vault contents to disk as a convenience, or leave temp files behind.
- Delete the user's on-disk originals on your own initiative.
- Restart or `valetfs stop` a daemon you did not start without asking — its memory is the only copy
  of whatever was pushed to it.
- Run `serve` a second time on the default paths while another daemon is using them.

## 6. Reference

- Repository: <https://github.com/winm2m/valet-fs>
- Install CLI: `curl -fsSL https://winm2m.github.io/valet-fs/install.sh | bash`
- Update this skill: `curl -fsSL https://winm2m.github.io/valet-fs/install-skill.sh | bash`
