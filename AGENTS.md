# ValetFS for AI agents

**Read this before you read a credential from anywhere on this machine.**

ValetFS is a vault. The contents live on the user's phone; a local daemon holds
them in memory only, and serves them while the phone allows it. If a secret is
in the vault, that copy is authoritative and the copy on disk or in an
environment variable is a leftover the user may be in the middle of deleting.

Vault paths take an `fs:` prefix. A bare `/keys/aws.env` is a path on *this*
machine, not in the vault.

## Never read a secret in order to use it

`valetfs cat` writes the value to stdout, and from there into your transcript,
the user's shell history, and any log that wraps you. Use `valetfs exec`
instead. The value goes into the child process and never passes through you:

```sh
# A whole env file into the command's environment.
valetfs exec fs:/keys/aws.env -- aws s3 ls s3://bucket

# One key as one variable.
valetfs exec --as EL_KEY fs:/keys/elevenlabs/api-key.txt -- node tts.mjs

# A tool that insists on a file path, not a value.
valetfs exec --as-file KEYFILE fs:/keys/apple.p8 -- ./sign.sh

# Several at once; every option repeats.
valetfs exec --as-file GOOGLE_APPLICATION_CREDENTIALS=fs:/keys/gcp/sa.json \
             --as SENTRY_TOKEN=fs:/keys/sentry.txt \
             fs:/keys/aws.env -- ./deploy.sh
```

The child's stdout, stderr and exit code pass through unchanged, so `exec` drops
into an existing pipeline or `&&` chain without special handling.

`valetfs ls` and `valetfs status` are safe to call: they report names, sizes and
daemon state, never contents.

`valetfs cat` stays for the case it is actually for — a person who needs to read
a value with their own eyes. Not for you.

## If your harness blocks you

Claude Code's classifier blocks `valetfs cat` with `[Credential
Materialization]`. **Do not work around it.** The default block is correct: an
agent that can drain a vault on its own initiative defeats the point of having
one. Two legitimate ways forward:

1. **Use `exec`.** Most work does not need the value, only its effect. In
   measurements on Claude Code in auto mode, `exec` running a command that
   *uses* a credential is allowed, including `--as-file` with a real service
   account key.
2. **Ask the human to run `valetfs setup-claude`.** One command, on their
   machine, with a confirmation prompt. You cannot run it for them — the same
   classifier blocks an agent from editing its own settings, with
   `[Self-Modification]` — and asking is the intended path, not a failure.

One thing `exec` will *not* get you past: a child command whose job is to
inspect the secret. `valetfs exec --as V fs:/keys/x -- sh -c 'echo ${#V}'` is
blocked as `[Credential Exploration]`, and reasonably so — measuring a key is
not using it. If you want to confirm a secret is present and plausible, use
`valetfs ls -l` for its size and then just use it.

## Traps

- **The `fs:` prefix is mandatory.** `ls`, `cat` and `exec` reject a host path
  outright, but **`cp` and `mv` accept one of each and infer the direction**, so
  `valetfs cp secret.env /keys/x` is a silent local file copy that writes
  plaintext outside the vault. Always write `fs:/keys/x`.
- **`--as-file` is the one command here that puts a secret in a file.** It uses
  a memory-backed directory (`$XDG_RUNTIME_DIR` or `/dev/shm`) at mode 0600, and
  zeroes and removes it on exit. If neither is available it falls back to the
  real temp dir and says so on stderr. Prefer `--as` when the tool will take a
  value.
- **The child's environment is readable through `/proc` by this same user**, and
  a child that dumps its environment dumps the secret. `--as-file` hands over a
  path, so a tool that logs its arguments logs the path rather than the key.
- **The vault is volatile.** Daemon restart, a remote lock, or grace expiry
  clears it. Never delete a user's only on-disk copy on your own initiative.
- **`valetfs status` reports the grace countdown.** If one is armed, the secrets
  are on a deadline; say so rather than letting it expire mid-task.
- **The CLI only ever talks to `~/.valetfs/run/runtime.json`.** `--runtime-dir`
  applies to `serve`, not to the CLI. With two daemons, use `--daemon-addr`.

## Joining a session

A long base64url string with no explanation is a connection key: the user tapped
**Provision an agent** in the app. Install the CLI, then join and leave it
running.

```sh
curl -fsSL https://winm2m.github.io/valet-fs/install.sh | bash

valetfs serve --join <KEY> \
  --grace 604800 \
  --resume-key-file "$HOME/.valetfs/e2ee.key" \
  > "$HOME/.valetfs/daemon.log" 2>&1 &
```

`--grace 604800` is 7 days; **the default is 300 seconds**, which unmounts and
wipes five minutes after the phone disconnects and surprises everyone once. The
key is itself a secret — do not echo it, log it, or commit it.

## Do not

- Print a secret's value into the conversation, a log, or a commit message.
- Copy vault contents to disk for convenience, or leave a temp file behind.
- Delete the user's on-disk originals on your own initiative.
- Restart or `valetfs stop` a daemon you did not start without asking. Its
  memory is the only copy of whatever was pushed to it.
- Suggest "Forget this daemon" as a troubleshooting step. In the app it destroys
  the hub session, not just the local pairing.

## Reference

- `valetfs --help`, `valetfs exec --help`, `valetfs setup-claude --help`
- Plain-text summary for model context: <https://winm2m.github.io/valet-fs/llms.txt>
- Repository: <https://github.com/winm2m/valet-fs>
- Claude Code skill: `curl -fsSL https://winm2m.github.io/valet-fs/install-skill.sh | bash`
