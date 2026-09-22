package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The documented form puts the variable name and the vault path in separate
// tokens. The composable form joins them with `=`. Both have to mean the same
// thing, because the first is what a person types and the second is what
// survives being extended to three secrets.
func TestParseExecArgsBothBindingForms(t *testing.T) {
	for _, args := range [][]string{
		{"--as", "EL_KEY", "fs:/keys/el.txt", "--", "node", "tts.mjs"},
		{"--as", "EL_KEY=fs:/keys/el.txt", "--", "node", "tts.mjs"},
		{"--as=EL_KEY=fs:/keys/el.txt", "--", "node", "tts.mjs"},
	} {
		b, argv, _, err := parseExecArgs(args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if len(b) != 1 || b[0].kind != execKindValue || b[0].name != "EL_KEY" || b[0].path != "fs:/keys/el.txt" {
			t.Errorf("%v: got %+v", args, b)
		}
		if strings.Join(argv, " ") != "node tts.mjs" {
			t.Errorf("%v: argv = %v", args, argv)
		}
	}
}

func TestParseExecArgsBareEnvFile(t *testing.T) {
	b, argv, _, err := parseExecArgs([]string{"fs:/keys/aws.env", "--", "aws", "s3", "ls"})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 1 || b[0].kind != execKindEnvFile || b[0].path != "fs:/keys/aws.env" {
		t.Fatalf("got %+v", b)
	}
	if len(argv) != 3 {
		t.Fatalf("argv = %v", argv)
	}
}

// Name-only bindings consume positional paths in the order they appeared, and
// whatever is left over is an env file. Getting this wrong would silently hand
// the wrong secret to the wrong variable, which is worse than refusing.
func TestParseExecArgsBindsInOrder(t *testing.T) {
	b, _, _, err := parseExecArgs([]string{
		"--as", "A", "--as-file", "B", "fs:/a", "fs:/b", "fs:/c.env", "--", "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []execBinding{
		{kind: execKindValue, name: "A", path: "fs:/a"},
		{kind: execKindFile, name: "B", path: "fs:/b"},
		{kind: execKindEnvFile, path: "fs:/c.env"},
	}
	if len(b) != len(want) {
		t.Fatalf("got %+v", b)
	}
	for i := range want {
		if b[i] != want[i] {
			t.Errorf("binding %d = %+v, want %+v", i, b[i], want[i])
		}
	}
}

func TestParseExecArgsRejections(t *testing.T) {
	cases := map[string][]string{
		"no separator":      {"fs:/keys/aws.env", "aws", "s3", "ls"},
		"nothing to run":    {"fs:/keys/aws.env", "--"},
		"nothing to inject": {"--", "aws", "s3", "ls"},
		"unbound --as":      {"--as", "A", "--", "true"},
		"bad var name":      {"--as", "9A=fs:/a", "--", "true"},
		"unknown option":    {"--nope", "--", "true"},
		"missing value":     {"--as", "--", "true"},
	}
	for name, args := range cases {
		if _, _, _, err := parseExecArgs(args); err == nil {
			t.Errorf("%s: expected an error for %v", name, args)
		}
	}
}

// Everything after `--` belongs to the child, including flags whose names
// collide with ours.
func TestParseExecArgsDoesNotEatChildFlags(t *testing.T) {
	_, argv, _, err := parseExecArgs([]string{"fs:/a.env", "--", "mytool", "--env", "prod", "--as", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv, " ") != "mytool --env prod --as x" {
		t.Fatalf("argv = %v", argv)
	}
}

func TestValidEnvName(t *testing.T) {
	for _, ok := range []string{"A", "_x", "AWS_ACCESS_KEY_ID", "a1"} {
		if !validEnvName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "1A", "a-b", "a b", "a=b", "a.b", "$A"} {
		if validEnvName(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestParseEnvFile(t *testing.T) {
	in := "" +
		"# a comment\n" +
		"\n" +
		"AWS_ACCESS_KEY_ID=AKIA123\n" +
		"export AWS_SECRET_ACCESS_KEY=abc/def+ghi\n" +
		"QUOTED='keep me'\n" +
		"DQUOTED=\"line1\\nline2\"\n" +
		"TRAILING_WS=value   \n" +
		"HASH=pass #word\n" +
		"EMPTY=\n"
	got, err := parseEnvFile([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"AWS_ACCESS_KEY_ID=AKIA123",
		"AWS_SECRET_ACCESS_KEY=abc/def+ghi",
		"QUOTED=keep me",
		"DQUOTED=line1\nline2",
		"TRAILING_WS=value",
		// A secret is more likely to contain " #" than a comment is to be
		// written on a credential's line, so the value is taken whole.
		"HASH=pass #word",
		"EMPTY=",
	}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseEnvFileCRLF(t *testing.T) {
	got, err := parseEnvFile([]byte("A=1\r\nB=2\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "A=1" || got[1] != "B=2" {
		t.Fatalf("got %q", got)
	}
}

// An error message is just another place a secret can end up, so a parse
// failure names the line number and nothing else.
func TestParseEnvFileErrorsHideContent(t *testing.T) {
	for _, in := range []string{"AKIAIOSFODNN7EXAMPLE\n", "9BAD=hunter2\n"} {
		_, err := parseEnvFile([]byte(in))
		if err == nil {
			t.Fatalf("expected an error for %q", in)
		}
		if strings.Contains(err.Error(), "AKIAIOSFODNN7EXAMPLE") || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("the error leaked file content: %v", err)
		}
	}
}

func TestTrimSecretNewline(t *testing.T) {
	cases := []struct{ in, want string }{
		{"key\n", "key"},
		{"key\r\n", "key"},
		{"key", "key"},
		{"key\n\n", "key\n"}, // only the one an editor adds
		{"", ""},
	}
	for _, c := range cases {
		if got := trimSecretNewline([]byte(c.in), false); got != c.want {
			t.Errorf("trim(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := trimSecretNewline([]byte("key\n"), true); got != "key\n" {
		t.Errorf("--keep-newline should keep it, got %q", got)
	}
}

// --as-file is the one path here that puts a secret into a file, so it has to
// clean up after itself even if the file is on a tmpfs.
func TestWriteSecretFileAndWipe(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "apple.p8")
	if err := writeSecretFile(p, []byte("-----BEGIN PRIVATE KEY-----")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}
	// Refusing to overwrite means a name collision cannot hand the child
	// somebody else's key.
	if err := writeSecretFile(p, []byte("other")); err == nil {
		t.Error("writeSecretFile should not overwrite an existing file")
	}
	wipeFile(p)
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("wipeFile left %s behind", p)
	}
}

func TestPrivateTempDirPrefersMemory(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	d, onDisk, err := privateTempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d)
	if onDisk {
		t.Error("a usable XDG_RUNTIME_DIR should not report a disk fallback")
	}
	if !strings.HasPrefix(d, os.Getenv("XDG_RUNTIME_DIR")) {
		t.Errorf("%s is not under XDG_RUNTIME_DIR", d)
	}
	st, err := os.Stat(d)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Errorf("mode = %v, want 0700", st.Mode().Perm())
	}
}

// Two vault paths can share a basename — fs:/keys/prod/sa.json and
// fs:/keys/stage/sa.json — so each --as-file gets its own subdirectory. Without
// that, the second one failed with "file exists" and the command never ran.
func TestAsFileSubdirsAvoidBasenameCollision(t *testing.T) {
	parent := t.TempDir()
	var paths []string
	for i := 0; i < 2; i++ {
		sub := filepath.Join(parent, strconv.Itoa(i))
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(sub, "sa.json")
		if err := writeSecretFile(p, []byte("{}")); err != nil {
			t.Fatalf("binding %d: %v", i, err)
		}
		paths = append(paths, p)
	}
	if paths[0] == paths[1] {
		t.Fatal("the two bindings resolved to the same file")
	}
	// The filename still carries the extension, which is how tools that sniff
	// .json/.p8/.pem recognise what they were handed.
	for _, p := range paths {
		if filepath.Base(p) != "sa.json" {
			t.Errorf("%s lost the vault file's name", p)
		}
	}
}
