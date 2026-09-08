package vault

import (
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
