package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// setup-claude is the answer to a problem that cannot be solved by telling an
// agent what to do. Claude Code blocks an agent from editing its own settings,
// which means the agent that most needs the vault open is the one that cannot
// open it. So the fix has to run where a person's hands already are: the same
// terminal where they ran install.sh and `serve --join`.

// The rules exec makes possible. cat is not here on purpose — see agentCatRule.
//
// Claude Code treats "Bash(cmd *)" and "Bash(cmd:*)" as the same rule, and a
// trailing " *" also matches the bare command, so "Bash(valetfs ls *)" covers
// plain `valetfs ls` too. The space matters: "Bash(valetfs ls*)" would also
// match a program named `valetfs lsof`-style. "Bash(valetfs status)" is exact
// because status takes no arguments worth allowing.
var agentAllowRules = []string{
	"Bash(valetfs exec *)",
	"Bash(valetfs ls *)",
	"Bash(valetfs status)",
}

// agentCatRule hands the agent whole secrets, so it is opt-in. Once `exec`
// exists, most work does not need it, and a rule that allows one `cat` allows
// every `cat` — the whole vault, not one use of one key.
const agentCatRule = "Bash(valetfs cat *)"

type setupClaudeOpts struct {
	printOnly bool
	yes       bool
	allowCat  bool
	path      string
}

func runSetupClaude(args []string) error {
	var o setupClaudeOpts
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, inline, hasInline := a, "", false
		if j := strings.Index(a, "="); j > 0 && strings.HasPrefix(a, "-") {
			name, inline, hasInline = a[:j], a[j+1:], true
		}
		switch name {
		case "-h", "--help":
			printSetupClaudeHelp(os.Stdout)
			return nil
		case "--print", "--dry-run":
			o.printOnly = true
		case "-y", "--yes":
			o.yes = true
		case "--allow-cat":
			o.allowCat = true
		case "--path":
			if hasInline {
				o.path = inline
				continue
			}
			if i+1 >= len(args) {
				return fmt.Errorf("--path needs a file")
			}
			i++
			o.path = args[i]
		default:
			return fmt.Errorf("setup-claude: unknown option %s", a)
		}
	}

	want := append([]string{}, agentAllowRules...)
	if o.allowCat {
		want = append(want, agentCatRule)
	}

	if o.printOnly {
		b, err := json.MarshalIndent(map[string]any{
			"permissions": map[string]any{"allow": want},
		}, "", "  ")
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(os.Stdout, string(b))
		return nil
	}

	target := o.path
	if target == "" {
		t, err := claudeSettingsPath()
		if err != nil {
			return err
		}
		target = t
	}

	old, err := os.ReadFile(target)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("setup-claude: %w", err)
	}
	existed := err == nil

	patched, added, err := patchClaudeSettings(old, want)
	if err != nil {
		return fmt.Errorf("setup-claude: %s: %w", target, err)
	}
	if len(added) == 0 {
		_, _ = fmt.Fprintf(os.Stdout, "Already allowed in %s. Nothing to do.\n", target)
		return nil
	}

	_, _ = fmt.Fprintf(os.Stdout, "Add to %s:\n", target)
	for _, r := range added {
		_, _ = fmt.Fprintf(os.Stdout, "  + %s\n", r)
	}
	if !o.allowCat && !containsRule(added, agentCatRule) {
		_, _ = fmt.Fprintln(os.Stdout,
			"  (cat is not included — use `valetfs exec` instead, or pass --allow-cat)")
	}
	if !o.yes {
		ok, err := confirm("Write it?")
		if err != nil {
			return err
		}
		if !ok {
			_, _ = fmt.Fprintln(os.Stdout, "Left unchanged.")
			return nil
		}
	}

	if existed {
		// Cheap insurance. This file is hand-maintained and holds settings
		// that have nothing to do with us.
		if err := os.WriteFile(target+".valetfs-backup", old, 0o600); err != nil {
			return fmt.Errorf("setup-claude: could not back up %s: %w", target, err)
		}
	}
	if err := writeFileAtomic(target, patched, 0o600); err != nil {
		return fmt.Errorf("setup-claude: %w", err)
	}
	_, _ = fmt.Fprintf(os.Stdout,
		"Wrote %s. Claude Code sessions started from now on can call valetfs without asking.\n", target)
	return nil
}

// claudeSettingsPath resolves the user-scope settings file: the one that
// applies in every project. A vault belongs to a machine, not a repository, so
// a per-project file would be the wrong scope even though it is easier to write.
func claudeSettingsPath() (string, error) {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return filepath.Join(d, "settings.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

// patchClaudeSettings merges the rules in and returns the new file plus the
// rules it actually added. It preserves every other key, and their order:
// re-sorting somebody's settings file to add three lines is rude, and it makes
// the diff unreadable for the one person who has to check what we did.
func patchClaudeSettings(old []byte, want []string) ([]byte, []string, error) {
	root, err := decodeOrdered(old)
	if err != nil {
		return nil, nil, err
	}

	perms := newOrderedObj()
	if raw, ok := root.get("permissions"); ok {
		perms, err = decodeOrdered(raw)
		if err != nil {
			return nil, nil, fmt.Errorf(`"permissions" is not an object: %w`, err)
		}
	}

	var allow []string
	if raw, ok := perms.get("allow"); ok {
		if err := json.Unmarshal(raw, &allow); err != nil {
			return nil, nil, fmt.Errorf(`"permissions.allow" is not an array of strings: %w`, err)
		}
	}

	var added []string
	for _, r := range want {
		if containsRule(allow, r) {
			continue
		}
		allow = append(allow, r)
		added = append(added, r)
	}
	if len(added) == 0 {
		return old, nil, nil
	}

	allowJSON, err := json.Marshal(allow)
	if err != nil {
		return nil, nil, err
	}
	perms.set("allow", allowJSON)
	permsJSON, err := perms.encode()
	if err != nil {
		return nil, nil, err
	}
	root.set("permissions", permsJSON)
	out, err := root.encode()
	if err != nil {
		return nil, nil, err
	}
	return append(out, '\n'), added, nil
}

// containsRule compares rules as written. Claude Code accepts "Bash(x *)" and
// "Bash(x:*)" as equivalent, so a user who already wrote the colon form gets
// the space form added alongside it. Harmless — two allow rules that overlap
// just both match — and better than trying to normalise a pattern language
// this program does not own.
func containsRule(rules []string, r string) bool {
	alt := r
	if strings.HasSuffix(r, " *)") {
		alt = strings.TrimSuffix(r, " *)") + ":*)"
	}
	for _, have := range rules {
		if have == r || have == alt {
			return true
		}
	}
	return false
}

var errNoPrompt = fmt.Errorf(
	"nothing is attached to stdin to answer the prompt; re-run with --yes, " +
		"or use --print and paste the JSON in yourself")

func confirm(prompt string) (bool, error) {
	if !stdinIsTerminal() {
		return false, errNoPrompt
	}
	_, _ = fmt.Fprintf(os.Stdout, "%s [y/N] ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		// `< /dev/null` is a character device, so it passes the check above and
		// then reads EOF. Treat that as "no one is here" rather than as a "no":
		// a script that meant to say yes deserves to be told about --yes.
		return false, errNoPrompt
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

func writeFileAtomic(dst string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".valetfs-settings-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, dst)
}

// orderedObj is a JSON object that remembers the order its keys came in.
// encoding/json cannot do this with a map, and this file exists to make a
// minimal, reviewable change to somebody else's configuration.
type orderedObj struct {
	keys   []string
	values map[string]json.RawMessage
}

func newOrderedObj() *orderedObj {
	return &orderedObj{values: map[string]json.RawMessage{}}
}

func (o *orderedObj) get(k string) (json.RawMessage, bool) {
	v, ok := o.values[k]
	return v, ok
}

func (o *orderedObj) set(k string, v json.RawMessage) {
	if _, ok := o.values[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.values[k] = v
}

// decodeOrdered reads a JSON object, keeping key order. An empty or
// whitespace-only input is an empty object, which is what a missing settings
// file should behave like.
func decodeOrdered(b []byte) (*orderedObj, error) {
	o := newOrderedObj()
	if len(bytes.TrimSpace(b)) == 0 {
		return o, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected a JSON object")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("expected an object key")
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		o.set(key, val)
	}
	// Consume the closing brace so that trailing garbage is an error rather
	// than something we silently drop on the way out.
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing content after the top-level object")
	}
	return o, nil
}

// encode re-emits the object with two-space indentation, which is what Claude
// Code itself writes, so the file does not churn every time somebody edits it
// by hand. json.Indent ignores the whitespace already in its input, so
// assembling compact JSON first and formatting once is enough.
func (o *orderedObj) encode() ([]byte, error) {
	var compact bytes.Buffer
	compact.WriteString("{")
	for i, k := range o.keys {
		if i > 0 {
			compact.WriteString(",")
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		compact.Write(kb)
		compact.WriteString(":")
		compact.Write(o.values[k])
	}
	compact.WriteString("}")

	var out bytes.Buffer
	if err := json.Indent(&out, compact.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// stdinIsTerminal decides whether there is a person here to answer the
// confirmation prompt. If there is not, setup-claude refuses rather than
// assuming consent: this command edits a file whose whole job is to decide what
// runs without asking.
func stdinIsTerminal() bool {
	st, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
