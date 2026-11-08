package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/anomalyco/valet-fs/internal/session"
)

func TestVaultsAuthorizeAddsAKeyOnceAndListsIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_vaults")
	k, _, err := session.LoadOrGenerateStatic("")
	if err != nil {
		t.Fatal(err)
	}
	pub := session.PubB64(k.Public)

	if err := runVaults([]string{"--authorized-vaults", path, "authorize", pub, "my", "laptop"}); err != nil {
		t.Fatal(err)
	}
	// Twice is a no-op, not a second line.
	if err := runVaults([]string{"--authorized-vaults", path, "authorize", pub}); err != nil {
		t.Fatal(err)
	}
	av, err := session.OpenAuthorizedVaults(path)
	if err != nil {
		t.Fatal(err)
	}
	if !av.Has(k.Public) {
		t.Fatal("the key was not recorded")
	}
	lines := av.List()
	if len(lines) != 1 || !strings.Contains(lines[0], "my laptop") {
		t.Fatalf("want one entry labelled 'my laptop', got %v", lines)
	}
}

func TestVaultsAuthorizeRejectsAnythingThatIsNotAKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_vaults")
	for _, bad := range []string{"", "not-base64!", "AAAA"} {
		args := []string{"--authorized-vaults", path, "authorize"}
		if bad != "" {
			args = append(args, bad)
		}
		if err := runVaults(args); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	av, _ := session.OpenAuthorizedVaults(path)
	if len(av.List()) != 0 {
		t.Fatalf("a rejected key was recorded: %v", av.List())
	}
}
