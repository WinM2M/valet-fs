package vfs

import (
	"testing"
)

func TestMemFSWriteReadRemove(t *testing.T) {
	m := New(0)

	if err := m.MkdirAll("/keys/github", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	want := []byte("ghp_secret_token_value")
	if err := m.Write("/keys/github/token", want, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := m.Read("/keys/github/token")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("read mismatch: got=%q want=%q", got, want)
	}

	names, err := m.List("/keys/github")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(names) != 1 || names[0] != "token" {
		t.Fatalf("unexpected list: %v", names)
	}

	if err := m.Remove("/keys/github/token"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := m.Read("/keys/github/token"); err == nil {
		t.Fatalf("expected error after remove")
	}
	if m.Used() != 0 {
		t.Fatalf("used should be 0, got %d", m.Used())
	}
}

func TestMemFSQuota(t *testing.T) {
	m := New(16)
	if err := m.Write("/a", []byte("0123456789ABCDEF"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := m.Write("/b", []byte("x"), 0o600); err != ErrQuota {
		t.Fatalf("expected ErrQuota, got %v", err)
	}
}

func TestMemFSWipeZerosData(t *testing.T) {
	m := New(0)
	payload := []byte("super-secret")
	if err := m.Write("/k", payload, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	snap := m.Snapshot()
	if string(snap["/k"]) != "super-secret" {
		t.Fatalf("snapshot wrong: %q", snap["/k"])
	}

	m.Wipe()

	if _, err := m.Read("/k"); err == nil {
		t.Fatalf("expected error after wipe")
	}
	if m.Used() != 0 {
		t.Fatalf("used should be 0 after wipe")
	}
}

func TestMemFSPathNormalization(t *testing.T) {
	m := New(0)
	if err := m.MkdirAll("/etc", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// "/../../etc/passwd" must be normalized to "/etc/passwd" inside the VFS,
	// so it cannot escape the in-memory root and touch the real filesystem.
	if err := m.Write("/../../etc/passwd", []byte("nope"), 0o600); err != nil {
		t.Fatalf("write inside vfs root should succeed, got %v", err)
	}
	got, err := m.Read("/etc/passwd")
	if err != nil || string(got) != "nope" {
		t.Fatalf("path was not normalized into vfs root: got=%q err=%v", got, err)
	}
	if err := m.Write("", nil, 0o600); err != ErrInvalidPath {
		t.Fatalf("expected ErrInvalidPath for empty path, got %v", err)
	}
}

func TestMemFSSnapshotIndependentCopy(t *testing.T) {
	m := New(0)
	_ = m.Write("/k", []byte("abc"), 0o600)
	snap := m.Snapshot()
	snap["/k"][0] = 'X'
	got, _ := m.Read("/k")
	if string(got) != "abc" {
		t.Fatalf("snapshot mutated source: %q", got)
	}
}
