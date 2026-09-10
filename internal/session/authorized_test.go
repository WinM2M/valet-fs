package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tmpPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "authorized_vaults")
}

// A missing file means trust-on-first-use, not a broken daemon. Failing to start
// because nothing has been pinned yet would make first pairing impossible.
func TestMissingFileMeansTrustOnFirstUse(t *testing.T) {
	a, err := OpenAuthorizedVaults(tmpPath(t))
	if err != nil {
		t.Fatalf("a missing list must not be an error: %v", err)
	}
	if len(a.Keys()) != 0 {
		t.Fatal("want an empty list")
	}
}

func TestAddPersistsAndIsIdempotent(t *testing.T) {
	path := tmpPath(t)
	k := mustKey(t)

	a, _ := OpenAuthorizedVaults(path)
	if err := a.Add(k.Public, DefaultLabel(time.Now())); err != nil {
		t.Fatalf("add: %v", err)
	}
	// A reconnecting vault must not grow the file a line at a time.
	if err := a.Add(k.Public, "again"); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if got := len(a.Keys()); got != 1 {
		t.Fatalf("want 1 entry, got %d", got)
	}

	reopened, err := OpenAuthorizedVaults(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !reopened.Has(k.Public) {
		t.Fatal("the pin did not survive a restart, which is the whole reason it is a file")
	}
}

func TestFilePermissionsAndComments(t *testing.T) {
	path := tmpPath(t)
	a, _ := OpenAuthorizedVaults(path)
	if err := a.Add(mustKey(t).Public, "phone"); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("want 0600, got %o", perm)
	}

	body, _ := os.ReadFile(path)
	text := string(body)
	if !strings.Contains(text, "trust-on-first-use") {
		t.Error("the file should explain what an empty list means")
	}
	if !strings.Contains(text, "phone") {
		t.Error("the label should be written out")
	}
}

func TestRemoveUnpins(t *testing.T) {
	path := tmpPath(t)
	keep, drop := mustKey(t), mustKey(t)
	a, _ := OpenAuthorizedVaults(path)
	_ = a.Add(keep.Public, "keep")
	_ = a.Add(drop.Public, "lost phone")

	removed, err := a.Remove(drop.Public)
	if err != nil || !removed {
		t.Fatalf("remove: %v removed=%v", err, removed)
	}
	if a.Has(drop.Public) {
		t.Fatal("the removed key is still authorised")
	}
	if !a.Has(keep.Public) {
		t.Fatal("removing one key must not drop the others")
	}

	// Removing something absent is not an error, so an un-pin can be retried.
	if removed, err := a.Remove(drop.Public); err != nil || removed {
		t.Fatalf("second remove: %v removed=%v", err, removed)
	}
}

func TestCommentsAndBlankLinesAreIgnored(t *testing.T) {
	path := tmpPath(t)
	k := mustKey(t)
	body := "# a comment\n\n   \n" + PubB64(k.Public) + "   my phone  \n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := OpenAuthorizedVaults(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(a.Keys()) != 1 || !a.Has(k.Public) {
		t.Fatalf("want exactly the one key, got %v", a.List())
	}
}

// A corrupt line must stop the daemon rather than being skipped: skipping would
// silently shrink the authorised set, and an empty set means "trust the next
// vault that turns up".
func TestGarbageIsAnErrorNotASkip(t *testing.T) {
	path := tmpPath(t)
	if err := os.WriteFile(path, []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAuthorizedVaults(path); err == nil {
		t.Fatal("a malformed entry must be reported, not ignored")
	}
}

// The pinned list is what Config.Authorised consumes, so the two must agree.
func TestKeysFeedTheSessionLayer(t *testing.T) {
	path := tmpPath(t)
	vk, dk := mustKey(t), mustKey(t)
	a, _ := OpenAuthorizedVaults(path)
	_ = a.Add(vk.Public, "phone")

	_, d, _, _ := establish(t, "sid-1", vk, dk, a.Keys())
	if !d.Established() {
		t.Fatal("a pinned vault must be accepted")
	}

	other := mustKey(t)
	_, d2, _, _ := establish(t, "sid-1", other, dk, a.Keys())
	if d2.Established() {
		t.Fatal("a vault that is not on the list must be refused")
	}
}

// The Noise static key is a different file from the v1 key on purpose: sharing
// one key pair across two protocols means a flaw in either is not confined to it.
func TestLoadOrGenerateStaticPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.key")

	first, reused, err := LoadOrGenerateStatic(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if reused {
		t.Fatal("a fresh file cannot be a reuse")
	}

	again, reused, err := LoadOrGenerateStatic(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reused {
		t.Fatal("the second call must report reuse")
	}
	if !subtleEqual(first.Public, again.Public) {
		t.Fatal("the identity changed across a restart")
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("a private key file must be 0600, got %o", perm)
	}
}

func TestEmptyPathGivesAnEphemeralKey(t *testing.T) {
	a, _, err := LoadOrGenerateStatic("")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := LoadOrGenerateStatic("")
	if err != nil {
		t.Fatal(err)
	}
	if subtleEqual(a.Public, b.Public) {
		t.Fatal("without a path each start must be a new identity")
	}
}

func TestCorruptKeyFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noise.key")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrGenerateStatic(path); err == nil {
		t.Fatal("a truncated key file must be reported, not silently replaced")
	}
}
