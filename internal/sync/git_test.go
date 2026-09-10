package sync

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommitWritesManifestOnly(t *testing.T) {
	dir := t.TempDir()
	repo, err := Open(filepath.Join(dir, "git"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	snap := map[string][]byte{
		"/keys/token": []byte("super-secret-token"),
	}
	hash, err := repo.Commit(snap, "test")
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if hash == "" {
		t.Fatalf("expected non-empty commit hash")
	}

	// The on-disk manifest must NOT contain the plaintext token body.
	manifest := mustReadFile(t, filepath.Join(repo.Dir(), "manifest.txt"))
	if strings.Contains(manifest, "super-secret-token") {
		t.Fatalf("manifest leaked plaintext: %q", manifest)
	}
	if !strings.Contains(manifest, "/keys/token") {
		t.Fatalf("manifest missing path entry: %q", manifest)
	}
}

func mustReadFile(t *testing.T, p string) string {
	t.Helper()
	data, err := readFile(p)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	return string(data)
}

// The old manifest stored a bare SHA-256 of each body, which let anyone reading
// the repository confirm a guessed secret — and git history kept that ability
// long after the secret was wiped. The fingerprint must be keyed.
func TestManifestFingerprintIsNotAGuessOracle(t *testing.T) {
	secret := []byte("super-secret-token")
	plain := sha256.Sum256(secret)
	snap := map[string][]byte{"/keys/token": secret}

	first, err := Open(filepath.Join(t.TempDir(), "git"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := first.Commit(snap, "test"); err != nil {
		t.Fatalf("commit: %v", err)
	}
	m1 := mustReadFile(t, filepath.Join(first.Dir(), "manifest.txt"))

	if strings.Contains(m1, hex.EncodeToString(plain[:])) {
		t.Fatal("manifest contains the unkeyed SHA-256 of the secret")
	}

	// A second repository over identical data must not agree, or the digest
	// would be reproducible by anyone holding a candidate value.
	second, err := Open(filepath.Join(t.TempDir(), "git"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := second.Commit(snap, "test"); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if m1 == mustReadFile(t, filepath.Join(second.Dir(), "manifest.txt")) {
		t.Fatal("two independent repositories produced the same fingerprint")
	}
}

func TestWipeClearsHistoryAndLeavesTheRepoUsable(t *testing.T) {
	repo, err := Open(filepath.Join(t.TempDir(), "git"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := repo.Commit(map[string][]byte{"/keys/token": []byte("x")}, "test"); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := readFile(filepath.Join(repo.Dir(), "manifest.txt")); err != nil {
		t.Fatalf("manifest should exist before wipe: %v", err)
	}

	if err := repo.Wipe(); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	if _, err := readFile(filepath.Join(repo.Dir(), "manifest.txt")); err == nil {
		t.Fatal("manifest survived the wipe")
	}

	// Locking must not leave the daemon needing a restart to serve again.
	if _, err := repo.Commit(map[string][]byte{"/keys/token": []byte("y")}, "after wipe"); err != nil {
		t.Fatalf("repo unusable after wipe: %v", err)
	}
}
