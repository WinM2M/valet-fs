package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// `exec` exists because `cat` is the wrong shape for the job. Reading a secret
// to use it means the value lands in stdout, and from there in a shell history,
// a log, or an AI agent's transcript — three places nobody audits. `exec` hands
// the value to a child process instead, so the only thing that crosses the
// terminal is the child's own output.
//
// That is not a permission trick. `exec` still needs read access to the vault.
// The difference is the blast radius: `cat` yields the secret itself, `exec`
// yields one command's worth of use of it.

type execKind int

const (
	execKindEnvFile execKind = iota // dotenv file; every KEY=VALUE is injected
	execKindValue                   // whole file body becomes one variable
	execKindFile                    // file is materialised; variable holds its path
)

// execBinding is one "take this vault path and make it reachable as X" request.
// Path is empty until the parser binds it, so that `--as NAME fs:/p` (name and
// path as separate tokens, the form that reads best in a shell) and
// `--as NAME=fs:/p` (the form that composes when there are several) can both
// land in the same structure.
type execBinding struct {
	kind execKind
	name string
	path string
}

// validEnvName rejects names the child's shell could not address anyway, and in
// doing so rejects the ones that would let a crafted vault file smuggle
// something odd into the environment block.
func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// parseExecArgs splits the invocation at the first bare `--`. Everything after
// it is the child command, untouched: the child gets to have its own `--env`
// flag without colliding with ours.
func parseExecArgs(args []string) ([]execBinding, []string, bool, error) {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		return nil, nil, false, fmt.Errorf("exec needs `--` before the command: " +
			"valetfs exec [options] <vault-path>... -- <command> [args...]")
	}
	opts, argv := args[:sep], args[sep+1:]
	if len(argv) == 0 {
		return nil, nil, false, fmt.Errorf("exec needs a command after `--`")
	}

	var (
		bindings   []execBinding
		positional []string
		keepNL     bool
	)
	// take reads a flag's value from `--flag=value` or the following token.
	take := func(i *int, name, inline string, has bool) (string, error) {
		if has {
			return inline, nil
		}
		if *i+1 >= len(opts) {
			return "", fmt.Errorf("%s needs a value", name)
		}
		*i++
		return opts[*i], nil
	}
	for i := 0; i < len(opts); i++ {
		a := opts[i]
		flagName, inline, hasInline := a, "", false
		if j := strings.Index(a, "="); j > 0 && strings.HasPrefix(a, "-") {
			flagName, inline, hasInline = a[:j], a[j+1:], true
		}
		switch flagName {
		case "-h", "--help":
			return nil, nil, false, errExecHelp
		case "--keep-newline":
			keepNL = true
		case "--env":
			v, err := take(&i, "--env", inline, hasInline)
			if err != nil {
				return nil, nil, false, err
			}
			bindings = append(bindings, execBinding{kind: execKindEnvFile, path: v})
		case "--as", "--as-file":
			kind := execKindValue
			if flagName == "--as-file" {
				kind = execKindFile
			}
			v, err := take(&i, flagName, inline, hasInline)
			if err != nil {
				return nil, nil, false, err
			}
			name, p := v, ""
			if j := strings.Index(v, "="); j > 0 {
				name, p = v[:j], v[j+1:]
			}
			if !validEnvName(name) {
				return nil, nil, false, fmt.Errorf("%s: %q is not a usable environment variable name", flagName, name)
			}
			bindings = append(bindings, execBinding{kind: kind, name: name, path: p})
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				return nil, nil, false, fmt.Errorf("exec: unknown option %s", a)
			}
			positional = append(positional, a)
		}
	}

	// Bind the name-only forms to positional paths in the order they appeared,
	// then read whatever is left over as env files. This is what makes
	// `--as EL_KEY fs:/keys/elevenlabs.txt -- node tts.mjs` mean the obvious
	// thing while still allowing several bindings in one command.
	next := 0
	for i := range bindings {
		if bindings[i].path != "" {
			continue
		}
		if next >= len(positional) {
			return nil, nil, false, fmt.Errorf("--%s %s has no vault path; "+
				"write `--as %s=fs:/path` or put the path after it",
				map[execKind]string{execKindValue: "as", execKindFile: "as-file"}[bindings[i].kind],
				bindings[i].name, bindings[i].name)
		}
		bindings[i].path = positional[next]
		next++
	}
	for _, p := range positional[next:] {
		bindings = append(bindings, execBinding{kind: execKindEnvFile, path: p})
	}
	if len(bindings) == 0 {
		return nil, nil, false, fmt.Errorf("exec needs at least one vault path to inject")
	}
	return bindings, argv, keepNL, nil
}

// errExecHelp is a sentinel: --help is not a failure, but it unwinds the
// parser the same way an error does.
var errExecHelp = fmt.Errorf("exec: help requested")

func runExec(client *http.Client, base, token string, args []string) error {
	bindings, argv, keepNL, err := parseExecArgs(args)
	if err != nil {
		if err == errExecHelp {
			printExecHelp(os.Stdout)
			return nil
		}
		return err
	}

	env := os.Environ()
	var tmpDir string
	var tmpFiles []string
	// Cleanup runs on every exit path, including the signal paths below. It
	// zeroes the bytes first: on a tmpfs that is the only copy, and unlink
	// alone would leave it readable to anything that already holds the fd.
	cleanup := func() {
		for _, f := range tmpFiles {
			wipeFile(f)
		}
		if tmpDir != "" {
			_ = os.RemoveAll(tmpDir)
		}
	}
	defer cleanup()

	for _, b := range bindings {
		if isHostPath(b.path) {
			return hintVaultPath("exec", b.path)
		}
		fsPath := toFSPathArg(b.path)
		body, err := fetchVaultFile(client, base, token, fsPath)
		if err != nil {
			return err
		}
		switch b.kind {
		case execKindEnvFile:
			vars, err := parseEnvFile(body)
			if err != nil {
				// The overwhelmingly common cause is a file holding one bare
				// value, so name the fix instead of just reporting the line.
				return fmt.Errorf("%s: %w. If it holds a bare value rather than "+
					"KEY=VALUE lines, use --as NAME=%s", b.path, err, b.path)
			}
			if len(vars) == 0 {
				return fmt.Errorf("%s: no KEY=VALUE lines found; "+
					"use --as NAME=%s if it holds a bare value", b.path, b.path)
			}
			env = append(env, vars...)
		case execKindValue:
			env = append(env, b.name+"="+trimSecretNewline(body, keepNL))
		case execKindFile:
			if tmpDir == "" {
				d, onDisk, err := privateTempDir()
				if err != nil {
					return err
				}
				tmpDir = d
				if onDisk {
					// Say it out loud, like `cp fs: -> host` does. The whole
					// point of this program is to keep secrets off disk, and
					// without a tmpfs this is writing one there.
					_, _ = fmt.Fprintf(os.Stderr,
						"note: no memory-backed temp dir available, so --as-file wrote under %s. "+
							"It is removed on exit, but it touched disk.\n", tmpDir)
				}
			}
			// Keep the vault file's name so tools that sniff extensions
			// (.p8, .json, .pem) still recognise what they were handed, and
			// give each binding its own subdirectory so that two vault paths
			// with the same basename — fs:/keys/prod/sa.json and
			// fs:/keys/stage/sa.json — do not collide.
			sub := filepath.Join(tmpDir, strconv.Itoa(len(tmpFiles)))
			if err := os.Mkdir(sub, 0o700); err != nil {
				return fmt.Errorf("exec: --as-file: %w", err)
			}
			dst := filepath.Join(sub, path.Base(fsPath))
			if err := writeSecretFile(dst, body); err != nil {
				return err
			}
			tmpFiles = append(tmpFiles, dst)
			env = append(env, b.name+"="+dst)
		}
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("exec %s: %w", argv[0], err)
	}

	// The child is in our process group, so the terminal already delivered
	// SIGINT and SIGQUIT to it. Catching them here is only about not dying
	// ourselves before cleanup runs — forwarding would deliver them twice.
	// SIGTERM and SIGHUP can arrive addressed to us alone, so those we relay.
	sigc := make(chan os.Signal, 4)
	signal.Notify(sigc, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigc:
				if s == syscall.SIGTERM || s == syscall.SIGHUP {
					_ = cmd.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()

	waitErr := cmd.Wait()
	close(done)
	signal.Stop(sigc)
	cleanup()
	tmpFiles, tmpDir = nil, ""

	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			// Pass the child's verdict through unchanged. A wrapper that
			// flattens exit codes breaks every `... && next-step` above it.
			// ExitCode() is -1 when a signal killed the child, so report
			// 128+signal the way a shell does rather than exiting 255.
			code := ee.ExitCode()
			if code < 0 {
				if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
					code = 128 + int(ws.Signal())
				} else {
					code = 1
				}
			}
			os.Exit(code)
		}
		return waitErr
	}
	return nil
}

// fetchVaultFile reads a vault file into memory. Errors name the path and never
// the contents: an error message is just another place a secret can end up.
func fetchVaultFile(client *http.Client, base, token, fsPath string) ([]byte, error) {
	isDir, err := fsPathIsDirWithErr(client, base, token, fsPath)
	if err != nil {
		return nil, fmt.Errorf("exec: cannot read fs:/%s: %w", strings.TrimPrefix(fsPath, "/"), err)
	}
	if isDir {
		return nil, fmt.Errorf("exec: fs:/%s is a directory", strings.TrimPrefix(fsPath, "/"))
	}
	q := url.Values{"path": []string{fsPath}}
	resp, err := apiReq(client, base, token, http.MethodGet, "/files", q, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// trimSecretNewline drops the trailing newline a text editor leaves behind.
// Keeping it is the more literal reading, but a key with "\n" glued to the end
// fails as an Authorization header in a way that is miserable to debug, so the
// default is to trim and `--keep-newline` is the escape hatch.
func trimSecretNewline(b []byte, keep bool) string {
	s := string(b)
	if keep {
		return s
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.TrimSuffix(s, "\r")
}

// parseEnvFile reads a dotenv file into `KEY=VALUE` strings, in file order.
//
// Values are taken literally to end of line. Most dotenv loaders strip a
// trailing `# comment` from unquoted values; this one does not, because a
// password containing " #" is more likely than a comment on a secret's line,
// and silently truncating a credential is the worst of the two failures.
func parseEnvFile(b []byte) ([]string, error) {
	var out []string
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		t = strings.TrimPrefix(t, "export ")
		t = strings.TrimSpace(t)
		eq := strings.Index(t, "=")
		if eq < 0 {
			return nil, fmt.Errorf("line %d is not KEY=VALUE", i+1)
		}
		key := strings.TrimSpace(t[:eq])
		if !validEnvName(key) {
			return nil, fmt.Errorf("line %d has an unusable variable name", i+1)
		}
		val := t[eq+1:]
		switch {
		case len(val) >= 2 && val[0] == '\'' && val[len(val)-1] == '\'':
			val = val[1 : len(val)-1]
		case len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"':
			val = unescapeDoubleQuoted(val[1 : len(val)-1])
		default:
			val = strings.TrimRight(val, " \t")
		}
		out = append(out, key+"="+val)
	}
	return out, nil
}

func unescapeDoubleQuoted(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			sb.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			sb.WriteByte('\n')
		case 'r':
			sb.WriteByte('\r')
		case 't':
			sb.WriteByte('\t')
		case '\\', '"':
			sb.WriteByte(s[i])
		default:
			sb.WriteByte('\\')
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

// privateTempDir prefers a memory-backed directory, so that `--as-file` stays
// inside the promise the rest of this program makes. It reports whether it had
// to fall back to real storage, because that is worth telling the user.
func privateTempDir() (string, bool, error) {
	for _, parent := range []string{os.Getenv("XDG_RUNTIME_DIR"), "/dev/shm"} {
		if parent == "" {
			continue
		}
		st, err := os.Stat(parent)
		if err != nil || !st.IsDir() {
			continue
		}
		d, err := os.MkdirTemp(parent, "valetfs-exec-")
		if err != nil {
			continue
		}
		return d, false, nil
	}
	d, err := os.MkdirTemp("", "valetfs-exec-")
	if err != nil {
		return "", false, fmt.Errorf("exec: no writable temp dir for --as-file: %w", err)
	}
	return d, true, nil
}

func writeSecretFile(dst string, body []byte) error {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("exec: --as-file: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return fmt.Errorf("exec: --as-file: %w", err)
	}
	return f.Close()
}

// wipeFile zeroes a materialised secret before unlinking it. Belt and braces:
// the file is normally on a tmpfs, but a process that still holds the fd sees
// zeroes rather than the key.
func wipeFile(p string) {
	if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
		if f, err := os.OpenFile(p, os.O_WRONLY, 0o600); err == nil {
			zeros := make([]byte, 4096)
			for left := st.Size(); left > 0; {
				n := int64(len(zeros))
				if left < n {
					n = left
				}
				if _, err := f.Write(zeros[:n]); err != nil {
					break
				}
				left -= n
			}
			_ = f.Sync()
			_ = f.Close()
		}
	}
	_ = os.Remove(p)
}
