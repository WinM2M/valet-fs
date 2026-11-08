package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newVaultDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// seed builds a vault under the given passphrase and puts one secret in it.
func seed(t *testing.T, dir, pass, body string) {
	t.Helper()
	SetPassphraseProvider(func() string { return pass })
	v, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	host := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(host, []byte(body), 0o600); err != nil {
		t.Fatalf("write host file: %v", err)
	}
	if err := v.Add(host, "/keys/aws.env"); err != nil {
		t.Fatalf("add: %v", err)
	}
}

func TestNewVaultUnderPassphraseIsNeitherLegacyNorUnprotected(t *testing.T) {
	dir := newVaultDir(t)
	seed(t, dir, "correct horse", "SECRET=1")

	SetPassphraseProvider(func() string { return "correct horse" })
	v, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if v.UsesLegacyPassphrase() {
		t.Error("a vault under a real passphrase must not report legacy")
	}
	if v.IsUnprotected() {
		t.Error("a vault under a real passphrase must not report unprotected")
	}
}

func TestVaultWithNoPassphraseReportsUnprotected(t *testing.T) {
	dir := newVaultDir(t)
	SetPassphraseProvider(func() string { return "" })
	v, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !v.IsUnprotected() {
		t.Error("an empty passphrase must be reported as unprotected")
	}
}

// A vault written by an older build opens without any passphrase configured,
// and must announce itself as legacy rather than looking healthy.
func TestLegacyVaultIsDetectedWithNoPassphraseConfigured(t *testing.T) {
	dir := newVaultDir(t)
	seed(t, dir, LegacyDefaultPassphrase, "SECRET=1")

	SetPassphraseProvider(func() string { return "" })
	v, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !v.UsesLegacyPassphrase() {
		t.Fatal("a vault encrypted with the published passphrase must report legacy")
	}
	got, err := v.Read("/keys/aws.env")
	if err != nil {
		t.Fatalf("legacy vault must stay readable so it can be rekeyed: %v", err)
	}
	if string(got) != "SECRET=1" {
		t.Fatalf("body mismatch: %q", got)
	}
}

func TestRekeyMovesTheVaultOffTheLegacyPassphrase(t *testing.T) {
	dir := newVaultDir(t)
	seed(t, dir, LegacyDefaultPassphrase, "SECRET=1")

	SetPassphraseProvider(func() string { return "" })
	v, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := v.Rekey("a new and private passphrase"); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if v.UsesLegacyPassphrase() || v.IsUnprotected() {
		t.Error("after rekey the vault must report neither legacy nor unprotected")
	}

	// Readable under the new passphrase...
	SetPassphraseProvider(func() string { return "a new and private passphrase" })
	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen with new passphrase: %v", err)
	}
	got, err := reopened.Read("/keys/aws.env")
	if err != nil || string(got) != "SECRET=1" {
		t.Fatalf("content lost across rekey: %q %v", got, err)
	}
	if reopened.UsesLegacyPassphrase() {
		t.Error("reopened vault still reports legacy")
	}

	// ...and no longer under the published one.
	SetPassphraseProvider(func() string { return LegacyDefaultPassphrase })
	if stale, err := Open(dir); err == nil {
		if _, rerr := stale.Read("/keys/aws.env"); rerr == nil {
			t.Fatal("the published passphrase must no longer decrypt the vault")
		}
	}
}

func TestRekeyRefusesWeakTargets(t *testing.T) {
	dir := newVaultDir(t)
	seed(t, dir, "start here", "SECRET=1")
	SetPassphraseProvider(func() string { return "start here" })
	v, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := v.Rekey(""); err == nil {
		t.Error("rekey to an empty passphrase must be refused")
	}
	if err := v.Rekey(LegacyDefaultPassphrase); err == nil {
		t.Error("rekey to the published passphrase must be refused")
	}
}

func blobNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestFailedRekeyLeavesTheOldVaultReadable(t *testing.T) {
	dir := newVaultDir(t)
	seed(t, dir, "the first passphrase", "SECRET=1")

	SetPassphraseProvider(func() string { return "the first passphrase" })
	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := blobNames(t, dir)

	beforeRekeyCommit = func() error { return errors.New("injected: disk full") }
	defer func() { beforeRekeyCommit = nil }()
	if err := v.Rekey("a second passphrase"); err == nil {
		t.Fatal("rekey should have failed")
	}
	beforeRekeyCommit = nil

	if got := blobNames(t, dir); len(got) != len(before) {
		t.Errorf("a failed rekey left stray blobs: before %v, after %v", before, got)
	}
	// The handle that failed must still work...
	if b, err := v.Read("/keys/aws.env"); err != nil || string(b) != "SECRET=1" {
		t.Fatalf("handle unreadable after failed rekey: %q %v", b, err)
	}
	// ...and so must a fresh open under the OLD passphrase.
	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("old passphrase no longer opens the vault: %v", err)
	}
	if b, err := reopened.Read("/keys/aws.env"); err != nil || string(b) != "SECRET=1" {
		t.Fatalf("content lost: %q %v", b, err)
	}
}

func TestBlobNamesDoNotRevealThePlaintextHash(t *testing.T) {
	dir := newVaultDir(t)
	const body = "PIN=123456"
	seed(t, dir, "a strong test passphrase", body)
	sum := sha256.Sum256([]byte(body))
	guess := hex.EncodeToString(sum[:]) + ".bin"
	for _, n := range blobNames(t, dir) {
		if n == guess {
			t.Fatal("blob file name is the SHA-256 of the plaintext")
		}
	}

	// A rekey must not bring the hash names back.
	SetPassphraseProvider(func() string { return "a strong test passphrase" })
	v, _ := Open(dir)
	if err := v.Rekey("another strong passphrase"); err != nil {
		t.Fatal(err)
	}
	for _, n := range blobNames(t, dir) {
		if n == guess {
			t.Fatal("rekey produced a hash-named blob")
		}
	}
	if len(blobNames(t, dir)) != 1 {
		t.Errorf("old blobs not cleaned up: %v", blobNames(t, dir))
	}
}

// legacyVault writes a vault the way builds before this change did: manifest is
// raw nonce||ciphertext, the salt lives in salt.bin, the blob is named for the
// SHA-256 of its plaintext. nonceFirst forces the first byte of the manifest's
// nonce.
func legacyVault(t *testing.T, dir, pass, body string, nonceFirst byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	salt := []byte("0123456789abcdef")
	if err := os.WriteFile(filepath.Join(dir, "salt.bin"), salt, 0o600); err != nil {
		t.Fatal(err)
	}
	h := &Vault{Dir: dir, pass: pass}
	key, err := h.deriveKey()
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	seal := func(first byte, plain []byte) []byte {
		nonce := make([]byte, gcm.NonceSize())
		nonce[0] = first
		return gcm.Seal(nonce, nonce, plain, nil)
	}
	sum := sha256.Sum256([]byte(body))
	sha := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, "blobs", sha+".bin"), seal(1, []byte(body)), 0o600); err != nil {
		t.Fatal(err)
	}
	mf := `{"entries":{"/keys/a":{"path":"/keys/a","blob_sha":"` + sha + `","size":5,"mode":384,"modified":"2026-01-01T00:00:00Z"}}}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), seal(nonceFirst, []byte(mf)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedManifestWhoseNonceStartsWithABraceStillOpens(t *testing.T) {
	dir := newVaultDir(t)
	legacyVault(t, dir, "a strong test passphrase", "hello", '{')
	SetPassphraseProvider(func() string { return "a strong test passphrase" })
	v, err := Open(dir)
	if err != nil {
		t.Fatalf("a valid vault was rejected because its nonce began with '{': %v", err)
	}
	if b, err := v.Read("/keys/a"); err != nil || string(b) != "hello" {
		t.Fatalf("read: %q %v", b, err)
	}
}

func TestLegacyVaultMigratesOnFirstWriteAndStaysReadable(t *testing.T) {
	dir := newVaultDir(t)
	legacyVault(t, dir, "a strong test passphrase", "hello", 7)
	SetPassphraseProvider(func() string { return "a strong test passphrase" })
	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(t.TempDir(), "x")
	_ = os.WriteFile(host, []byte("new"), 0o600)
	if err := v.Add(host, "/keys/b"); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after the manifest moved to the new format: %v", err)
	}
	for path, want := range map[string]string{"/keys/a": "hello", "/keys/b": "new"} {
		if b, err := reopened.Read(path); err != nil || string(b) != want {
			t.Errorf("%s: %q %v", path, b, err)
		}
	}
}

func TestRemoveDeletesTheBlob(t *testing.T) {
	dir := newVaultDir(t)
	seed(t, dir, "a strong test passphrase", "gone soon")
	SetPassphraseProvider(func() string { return "a strong test passphrase" })
	v, _ := Open(dir)
	if err := v.Remove("/keys/aws.env"); err != nil {
		t.Fatal(err)
	}
	if n := blobNames(t, dir); len(n) != 0 {
		t.Errorf("blob left behind after Remove: %v", n)
	}
}
