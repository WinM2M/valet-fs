package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPatchClaudeSettingsFromEmpty(t *testing.T) {
	out, added, err := patchClaudeSettings(nil, agentAllowRules)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != len(agentAllowRules) {
		t.Fatalf("added = %q", added)
	}
	if got := allowRulesOf(t, out); strings.Join(got, ",") != strings.Join(agentAllowRules, ",") {
		t.Errorf("allow = %q", got)
	}
}

// Running it twice has to be a no-op. A person runs this once and forgets, and
// the next run must not append duplicates to a file they maintain by hand.
func TestPatchClaudeSettingsIsIdempotent(t *testing.T) {
	first, _, err := patchClaudeSettings(nil, agentAllowRules)
	if err != nil {
		t.Fatal(err)
	}
	second, added, err := patchClaudeSettings(first, agentAllowRules)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 0 {
		t.Errorf("second run wanted to add %q", added)
	}
	if string(second) != string(first) {
		t.Errorf("second run rewrote the file:\n%s", second)
	}
}

// The settings file holds hooks, plugins and a theme that have nothing to do
// with us. Reordering it to add three lines would make the diff unreadable for
// the one person who has to check what we did.
func TestPatchClaudeSettingsPreservesEverythingElse(t *testing.T) {
	old := `{
  "cleanupPeriodDays": 3650,
  "hooks": {
    "Stop": [
      { "hooks": [ { "type": "command", "command": "/x/stop.sh", "timeout": 30 } ] }
    ]
  },
  "theme": "dark",
  "permissions": {
    "deny": [ "Bash(rm -rf *)" ],
    "allow": [ "Bash(gh pr *)" ]
  }
}`
	out, added, err := patchClaudeSettings([]byte(old), agentAllowRules)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 3 {
		t.Fatalf("added = %q", added)
	}

	// Key order survives, top level and inside permissions.
	wantOrder := []string{"cleanupPeriodDays", "hooks", "theme", "permissions"}
	if got := topLevelKeyOrder(t, out); strings.Join(got, ",") != strings.Join(wantOrder, ",") {
		t.Errorf("top-level key order = %q", got)
	}

	var parsed struct {
		CleanupPeriodDays int             `json:"cleanupPeriodDays"`
		Theme             string          `json:"theme"`
		Hooks             json.RawMessage `json:"hooks"`
		Permissions       struct {
			Deny  []string `json:"deny"`
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if parsed.CleanupPeriodDays != 3650 || parsed.Theme != "dark" {
		t.Errorf("unrelated keys changed: %+v", parsed)
	}
	if !strings.Contains(string(parsed.Hooks), "/x/stop.sh") {
		t.Errorf("hooks lost: %s", parsed.Hooks)
	}
	if len(parsed.Permissions.Deny) != 1 || parsed.Permissions.Deny[0] != "Bash(rm -rf *)" {
		t.Errorf("deny rules changed: %q", parsed.Permissions.Deny)
	}
	// The user's own allow rule stays first; ours are appended.
	if parsed.Permissions.Allow[0] != "Bash(gh pr *)" {
		t.Errorf("allow = %q", parsed.Permissions.Allow)
	}
}

// cat is opt-in, because a rule that allows one cat allows every cat: the whole
// vault, rather than one command's use of one key.
func TestPatchClaudeSettingsOmitsCatByDefault(t *testing.T) {
	out, _, err := patchClaudeSettings(nil, agentAllowRules)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range allowRulesOf(t, out) {
		if strings.Contains(r, "cat") {
			t.Errorf("cat should not be allowed by default, found %q", r)
		}
	}
	withCat, added, err := patchClaudeSettings(out, append(append([]string{}, agentAllowRules...), agentCatRule))
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != agentCatRule {
		t.Fatalf("added = %q", added)
	}
	if !strings.Contains(string(withCat), agentCatRule) {
		t.Error("--allow-cat did not add the rule")
	}
}

// Claude Code reads "Bash(x *)" and "Bash(x:*)" as the same rule. Somebody who
// already wrote the colon form is already covered, so we must not add a second
// rule that means exactly the same thing.
func TestContainsRuleAcceptsTheColonForm(t *testing.T) {
	existing := []string{"Bash(valetfs exec:*)", "Bash(valetfs ls:*)", "Bash(valetfs status)"}
	for _, r := range agentAllowRules {
		if !containsRule(existing, r) {
			t.Errorf("%q should already be covered by the colon form", r)
		}
	}
	if containsRule(existing, agentCatRule) {
		t.Error("cat is not in that list")
	}
}

func TestPatchClaudeSettingsRejectsGarbage(t *testing.T) {
	for name, in := range map[string]string{
		"not json":          `{ nope`,
		"not an object":     `[1,2,3]`,
		"permissions wrong": `{"permissions": 7}`,
		"allow wrong":       `{"permissions": {"allow": "Bash(x)"}}`,
		"trailing content":  `{"theme":"dark"} {"theme":"light"}`,
	} {
		if _, _, err := patchClaudeSettings([]byte(in), agentAllowRules); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func allowRulesOf(t *testing.T, b []byte) []string {
	t.Helper()
	var parsed struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, b)
	}
	return parsed.Permissions.Allow
}

func topLevelKeyOrder(t *testing.T, b []byte) []string {
	t.Helper()
	o, err := decodeOrdered(b)
	if err != nil {
		t.Fatal(err)
	}
	return o.keys
}
