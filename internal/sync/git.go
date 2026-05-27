// Package sync persists VFS change history as a local git repository of diffs.
//
// SECURITY NOTE: To satisfy AGENT.md §2 "tokens never appear on disk in plain
// text", we never write the raw file body of a tracked file into the working
// tree. Instead we record a SHA-256 hash + size + size-classification per
// file path, which is sufficient for the mobile app to detect "something
// changed at /github/token" without ever observing the token material.
//
// The real plaintext stays exclusively in the MemFS heap and is shipped
// over the encrypted WebRTC DataChannel directly to the paired mobile app.
package sync

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	return &Repo{dir: dir, repo: repo}, nil
}

// Dir returns the on-disk path of the diff repo.
func (r *Repo) Dir() string { return r.dir }

// Commit records the current MemFS snapshot as a "manifest" commit. The
// manifest contains one line per file: "<sha256> <size> <path>".
func (r *Repo) Commit(snapshot map[string][]byte, message string) (string, error) {
	manifest := buildManifest(snapshot)
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

// Wipe forcefully removes the on-disk repository. Call this during shutdown
// to make sure no manifest stragglers linger after the daemon exits.
func (r *Repo) Wipe() error {
	return os.RemoveAll(r.dir)
}

func buildManifest(snapshot map[string][]byte) string {
	paths := make([]string, 0, len(snapshot))
	for p := range snapshot {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var b strings.Builder
	for _, p := range paths {
		data := snapshot[p]
		sum := sha256.Sum256(data)
		fmt.Fprintf(&b, "%s %d %s\n", hex.EncodeToString(sum[:]), len(data), p)
	}
	return b.String()
}
