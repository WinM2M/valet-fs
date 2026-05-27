package sync

import (
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
