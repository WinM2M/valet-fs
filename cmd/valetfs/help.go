package main

import (
	"fmt"
	"io"
)

// Agents reach for --help before they read a README, so the guidance about not
// materialising secrets has to live here, not only in the docs.

func printUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `valetfs — a vault whose contents live on the user's phone and are served to
this machine, in memory only, while the phone allows it.

usage:
  valetfs serve [--join <KEY>] [options]   run the daemon (this is what holds the vault)
  valetfs exec <vault-path>... -- <cmd>    run a command with a secret in its environment
  valetfs status                           daemon state, bytes used, grace countdown
  valetfs ls [-la] fs:/keys                list what the vault holds
  valetfs cat fs:/keys/x                   print a secret (see the note below)
  valetfs cp|mv|rm|mkdir|rmdir ...         move files in and out of the vault
  valetfs setup-claude [--print]           let Claude Code call valetfs unprompted
  valetfs vault <subcommand>               manage a vault stored on this machine
  valetfs vaults <list|forget|forget-all>  manage the identities this daemon accepts
  valetfs completion bash                  shell completion
  valetfs --version

Vault paths take an "fs:" prefix, as in fs:/keys/aws.env. A bare /keys/aws.env
is a path on this machine.

AI AGENTS: READ THIS FIRST.
  Do not read a secret in order to use it. "valetfs cat" puts the value in your
  stdout, and from there into your transcript. Use exec instead, so the value
  goes into the child process and never through you:

      valetfs exec fs:/keys/aws.env -- aws s3 ls s3://bucket
      valetfs exec --as EL_KEY fs:/keys/elevenlabs.txt -- node tts.mjs
      valetfs exec --as-file KEYFILE fs:/keys/apple.p8 -- ./sign.sh

  "valetfs ls" and "valetfs status" are safe to call. If your harness blocks
  cat — Claude Code reports [Credential Materialization] — do not work around
  it. Use exec, or ask the human to run "valetfs setup-claude" once.

  More: "valetfs exec --help", AGENTS.md in the repository, or
  https://winm2m.github.io/valet-fs/llms.txt

Run "valetfs <command> --help" for one command. cat is for the cases where a
person needs to read a value with their own eyes.

Global options: -v/--verbose (connection detail on serve and vault),
--daemon-addr=host:port (target a daemon other than the default runtime).

Docs: https://github.com/winm2m/valet-fs
`)
}

func printExecHelp(w io.Writer) {
	_, _ = fmt.Fprint(w, `valetfs exec — run a command with vault secrets in its environment.

The value goes into the child process. exec never writes it to stdout, to a
log, or to its own output, so it does not pass through a shell history or an AI
agent's transcript the way cat does. exec still needs read access to the vault;
what differs is the blast radius. cat yields the secret, exec yields one
command's worth of use of it.

usage:
  valetfs exec [options] <vault-path>... -- <command> [args...]

options:
  --env <vault-path>            Inject every KEY=VALUE from a dotenv file.
                                A bare positional path means the same thing.
  --as NAME=<vault-path>        Inject the whole file body as $NAME.
  --as NAME <vault-path>        Same, with the path as the next argument.
  --as-file NAME=<vault-path>   Materialise the file; set $NAME to its path.
  --as-file NAME <vault-path>   Same, with the path as the next argument.
  --keep-newline                Keep the trailing newline on --as values. It is
                                trimmed by default: a key with a newline glued
                                on fails as an Authorization header in a way
                                that is miserable to debug.
  --daemon-addr=host:port       Target a daemon other than the default runtime.

Every option is repeatable, so one command can inject several secrets.

examples:
  # Whole env file into the child's environment.
  valetfs exec fs:/keys/aws.env -- aws s3 ls s3://bucket

  # One key, one variable.
  valetfs exec --as EL_KEY fs:/keys/elevenlabs/api-key.txt -- node tts.mjs

  # A tool that wants a file path, not a value.
  valetfs exec --as-file KEYFILE fs:/keys/apple.p8 -- ./sign.sh

  # Several at once.
  valetfs exec --as-file GOOGLE_APPLICATION_CREDENTIALS=fs:/keys/gcp-sa.json \
               --as SENTRY_TOKEN=fs:/keys/sentry.txt \
               fs:/keys/aws.env -- ./deploy.sh

  # Log in to gcloud without the key crossing your terminal.
  valetfs exec --as-file K fs:/keys/gcp-sa.json -- \
    sh -c 'gcloud auth activate-service-account --key-file="$K"'

notes:
  The child's exit code becomes this command's exit code, so && chains behave.
  The child's own stdout and stderr pass through untouched — that is the result
  you are meant to see.

  Dotenv parsing takes values literally to end of line; it does not strip a
  trailing "# comment" from an unquoted value, because truncating a credential
  is worse than keeping a stray comment. Quote the value to keep it exactly.

  --as-file writes to a memory-backed directory ($XDG_RUNTIME_DIR or /dev/shm)
  at mode 0600, then zeroes and removes it when the command exits. With neither
  available it falls back to the real temp dir and says so on stderr.

  Anything in the child's environment is readable through /proc by this same
  user, and a child that dumps its own environment will dump the secret.
  --as-file hands over a path, so a child that logs its arguments logs the path
  rather than the key.
`)
}

func printSetupClaudeHelp(w io.Writer) {
	_, _ = fmt.Fprint(w, `valetfs setup-claude — let Claude Code call valetfs without a prompt each time.

Claude Code stops an agent from editing its own settings, and stops it from
reading a credential out of the vault by default. Both are correct: an agent
that can open the vault on its own initiative defeats the point of a vault.
This command is the way through, and it is meant for a person to run, once, on
this machine.

usage:
  valetfs setup-claude [options]

options:
  --print          Print the JSON that would be merged; write nothing.
  --yes            Skip the confirmation prompt. Required when stdin is not a
                   terminal.
  --allow-cat      Also allow "valetfs cat", which hands whole secrets to the
                   agent. Off by default, because exec covers most uses.
  --path <file>    Patch a specific settings file instead of the user's.

what it adds:
  "permissions": { "allow": [
    "Bash(valetfs exec *)",
    "Bash(valetfs ls *)",
    "Bash(valetfs status)"
  ] }

  Write and delete — cp, mv, rm — are deliberately left out: emptying a vault
  should take a confirmation. So is cat; add it with --allow-cat if you have a
  tool that cannot be driven through exec.

where it writes:
  $CLAUDE_CONFIG_DIR/settings.json when that variable is set, otherwise
  ~/.claude/settings.json. That is the user-scope file, the one that applies in
  every project, which is the right scope here: a vault belongs to a machine,
  not to a repository.

  Existing keys and their order are preserved, and the previous file is kept
  beside it as settings.json.valetfs-backup. Running it a second time changes
  nothing. New rules apply to Claude Code sessions started afterwards.
`)
}
