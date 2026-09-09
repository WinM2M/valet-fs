package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// "fs:" is what marks the vault, so an absolute path is a host path. That is a
// coin toss for something like /keys/aws.env, which reads as a vault path to a
// human, and the error has to say so instead of just refusing.
func TestIsHostPath(t *testing.T) {
	host := []string{"/tmp/x", "./x", "../x", "/keys/aws.env"}
	for _, p := range host {
		if !isHostPath(p) {
			t.Errorf("%q should be a host path", p)
		}
	}
	vault := []string{"fs:/keys/aws.env", "fs:keys/aws.env", "keys/aws.env", "aws.env"}
	for _, p := range vault {
		if isHostPath(p) {
			t.Errorf("%q should not be a host path", p)
		}
	}
}

func TestLooksLikeVaultPath(t *testing.T) {
	if !looksLikeVaultPath("/keys/aws.env") {
		t.Error("an absolute path that does not exist here should read as a vault path")
	}

	// A real file is taken at face value, however vault-ish it looks.
	dir := t.TempDir()
	real := filepath.Join(dir, "aws.env")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if looksLikeVaultPath(real) {
		t.Error("an existing file must not be second-guessed")
	}

	for _, p := range []string{"./x", "../x", "relative/x", "fs:/keys/x"} {
		if looksLikeVaultPath(p) {
			t.Errorf("%q is not an absolute path", p)
		}
	}
}

func TestHintVaultPathNamesTheFix(t *testing.T) {
	err := hintVaultPath("cat", "/keys/aws.env")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "fs:/keys/aws.env") {
		t.Errorf("the error should suggest the fs: form, got: %v", err)
	}

	dir := t.TempDir()
	real := filepath.Join(dir, "f")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := hintVaultPath("cat", real).Error(); strings.Contains(got, "Did you mean") {
		t.Errorf("an existing host file should not get a vault suggestion, got: %v", got)
	}
}

func TestToFSPathArg(t *testing.T) {
	cases := map[string]string{
		"fs:/keys/aws.env": "keys/aws.env",
		"/keys/aws.env":    "keys/aws.env",
		"keys/aws.env":     "keys/aws.env",
		"fs:/":             "/",
		"":                 "/",
	}
	for in, want := range cases {
		if got := toFSPathArg(in); got != want {
			t.Errorf("toFSPathArg(%q) = %q, want %q", in, got, want)
		}
	}
}
