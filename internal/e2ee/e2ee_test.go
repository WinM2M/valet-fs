package e2ee

import (
	"bytes"
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
