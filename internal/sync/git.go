// Package sync persists VFS change history as a local git repository of diffs.
//
// SECURITY NOTE: To satisfy AGENT.md §2 "tokens never appear on disk in plain
// text", we never write the raw file body of a tracked file into the working
// tree. Instead we record a fingerprint + size per file path, which is
// sufficient for the mobile app to detect "something changed at /github/token"
// without ever observing the token material.
//
// The fingerprint is an HMAC under a key generated fresh in memory on every
// Open, never written down. A bare SHA-256 would have been a verification
// oracle: anyone reading the repository could confirm a guessed secret by
// hashing it, and git history keeps that ability long after the secret itself
// has been wiped. Keying the digest means the on-disk record is useless to
// anyone who was not inside this process.
//
// The real plaintext stays exclusively in the MemFS heap and is shipped
// over the encrypted channel directly to the paired mobile app.
package sync

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Repo wraps an ephemeral on-disk git repository used to track diff metadata.
type Repo struct {
	dir  string
	repo *git.Repository
	// key salts the per-path fingerprints. It lives only in this process's
	// memory and is regenerated on every Open, so a repository left behind by a
	// killed daemon cannot be used to test guesses against past secrets.
	key []byte
}

// Open initialises (or re-opens) a repository at dir. The directory is created
// with 0o700 permissions if missing.
func Open(dir string) (*Repo, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir git dir: %w", err)
	}
	repo, err := git.PlainOpen(dir)
	if err != nil {
		repo, err = git.PlainInit(dir, false)
		if err != nil {
			return nil, fmt.Errorf("git init: %w", err)
		}
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("fingerprint key: %w", err)
	}
	return &Repo{dir: dir, repo: repo, key: key}, nil
}

// Dir returns the on-disk path of the diff repo.
func (r *Repo) Dir() string { return r.dir }

// Commit records the current MemFS snapshot as a "manifest" commit. The
// manifest contains one line per file: "<sha256> <size> <path>".
func (r *Repo) Commit(snapshot map[string][]byte, message string) (string, error) {
	manifest := buildManifest(snapshot, r.key)
	manifestPath := filepath.Join(r.dir, "manifest.txt")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		return "", fmt.Errorf("write manifest: %w", err)
	}

	wt, err := r.repo.Worktree()
	if err != nil {
		return "", err
	}
	if _, err := wt.Add("manifest.txt"); err != nil {
		return "", err
	}

	status, err := wt.Status()
	if err != nil {
		return "", err
	}
	if status.IsClean() {
		return "", nil // nothing to commit
	}

	hash, err := wt.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "valetd",
			Email: "valetd@localhost",
			When:  time.Now(),
		},
		AllowEmptyCommits: false,
	})
	if err != nil {
		return "", err
	}
	return hash.String(), nil
}

// Wipe forcefully removes the on-disk repository, history included, and starts
// an empty one in its place. Call it on every path that wipes the heap, not
// only shutdown: a lock that clears the secrets but leaves their change history
// on disk has not really locked anything.
//
// Re-initialising (rather than just deleting) keeps the Repo usable afterwards,
// so a daemon that locks and is then re-served does not need a restart.
func (r *Repo) Wipe() error {
	if err := os.RemoveAll(r.dir); err != nil {
		return err
	}
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return err
	}
	repo, err := git.PlainInit(r.dir, false)
	if err != nil {
		return fmt.Errorf("git re-init after wipe: %w", err)
	}
	r.repo = repo
	// A new history deserves a new key; the old fingerprints are gone anyway.
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("fingerprint key: %w", err)
	}
	r.key = key
	return nil
}

func buildManifest(snapshot map[string][]byte, key []byte) string {
	paths := make([]string, 0, len(snapshot))
	for p := range snapshot {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var b strings.Builder
	for _, p := range paths {
		data := snapshot[p]
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		fmt.Fprintf(&b, "%s %d %s\n", hex.EncodeToString(mac.Sum(nil)), len(data), p)
	}
	return b.String()
}
