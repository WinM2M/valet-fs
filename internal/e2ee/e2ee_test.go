package e2ee

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyAgreement(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	ka, err := deriveKey(a.Priv, b.Pub)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := deriveKey(b.Priv, a.Pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ka, kb) {
		t.Fatal("derived keys differ between peers")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()
	ka, _ := deriveKey(a.Priv, b.Pub)
	kb, _ := deriveKey(b.Priv, a.Pub)
	sa, _ := newSession(ka)
	sb, _ := newSession(kb)

	msg := []byte(`{"v":1,"type":"REQ","method":"WRITE"}`)
	ct, err := sa.seal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(ct), []byte("WRITE")) {
		t.Fatal("ciphertext leaks plaintext")
	}
	pt, err := sb.open(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("round trip mismatch: %q", pt)
	}
}

func TestTamperFails(t *testing.T) {
	a, _ := Generate()
	k, _ := deriveKey(a.Priv, a.Pub)
	s, _ := newSession(k)
	ct, _ := s.seal([]byte("secret"))
	// flip a character in the base64 body
	bad := []byte(ct)
	bad[len(bad)-2] ^= 0x01
	if _, err := s.open(string(bad)); err == nil {
		t.Fatal("expected open to fail on tampered ciphertext")
	}
}

func TestLoadOrGeneratePersistsIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "e2ee.key")

	first, reused, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if reused {
		t.Fatal("first call reported a reused key for a path that did not exist")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("key file not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}

	second, reused, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !reused {
		t.Error("second call did not report the key as reused")
	}
	// The public key is what the hub pins for the session's lifetime, so a
	// restart must republish exactly the same value or the rejoin is rejected.
	if second.PubB64() != first.PubB64() {
		t.Errorf("pub changed across restart: %q -> %q", first.PubB64(), second.PubB64())
	}
	if second.Priv != first.Priv {
		t.Error("private key changed across restart")
	}
}

func TestLoadOrGenerateRejectsShortKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e2ee.key")
	if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrGenerate(path); err == nil {
		t.Fatal("truncated key file accepted; want an error")
	}
}
