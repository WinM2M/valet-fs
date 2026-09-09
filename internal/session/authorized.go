package session

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// AuthorizedVaults is the daemon's list of vault identities it will accept —
// SSH's authorized_keys, for the other direction of trust than the one ValetFS
// already had. The app has pinned the daemon's key since v0.1; this is the half
// that was missing.
//
// It is a file rather than memory because a daemon restarts, and a pin that dies
// with the process means trust-on-first-use every time, which is barely trust at
// all. The entries are public keys, so the file is not secret; it is 0600
// because anything that can write it decides who may read the vault, and 0600 is
// the honest boundary — whoever can edit this can also replace the binary.
//
// Zero entries means trust-on-first-use: the first vault to complete a handshake
// is recorded, and a different one afterwards is refused. That is the best the
// QR flow can do, and the reverse-join flow does better by carrying the vault's
// key inside the connection key the user physically hands over.
type AuthorizedVaults struct {
	path string

	mu      sync.Mutex
	entries []authEntry
}

type authEntry struct {
	pub   []byte
	label string
}

// OpenAuthorizedVaults reads the list at path, creating nothing. A missing file
// is not an error: it means trust-on-first-use.
func OpenAuthorizedVaults(path string) (*AuthorizedVaults, error) {
	a := &AuthorizedVaults{path: path}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return a, nil
		}
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		pub, err := ParsePub(fields[0])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		label := ""
		if len(fields) > 1 {
			label = strings.Join(fields[1:], " ")
		}
		a.entries = append(a.entries, authEntry{pub: pub, label: label})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return a, nil
}

// Keys returns the authorised public keys, for handing to Config.Authorised.
// Empty means trust-on-first-use.
func (a *AuthorizedVaults) Keys() [][]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([][]byte, 0, len(a.entries))
	for _, e := range a.entries {
		out = append(out, e.pub)
	}
	return out
}

// Has reports whether pub is already authorised.
func (a *AuthorizedVaults) Has(pub []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if subtleEqual(e.pub, pub) {
			return true
		}
	}
	return false
}

// Add records pub and writes the file. Adding a key that is already present is a
// no-op rather than a duplicate, so a reconnecting vault does not grow the file
// a line at a time.
func (a *AuthorizedVaults) Add(pub []byte, label string) error {
	if len(pub) != 32 {
		return errors.New("session: public key must be 32 bytes")
	}
	a.mu.Lock()
	for _, e := range a.entries {
		if subtleEqual(e.pub, pub) {
			a.mu.Unlock()
			return nil
		}
	}
	a.entries = append(a.entries, authEntry{pub: append([]byte(nil), pub...), label: label})
	a.mu.Unlock()
	return a.save()
}

// Remove drops pub, which is how a user un-pins a daemon after losing a phone.
// Reports whether anything was removed.
func (a *AuthorizedVaults) Remove(pub []byte) (bool, error) {
	a.mu.Lock()
	kept := a.entries[:0]
	removed := false
	for _, e := range a.entries {
		if subtleEqual(e.pub, pub) {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	a.entries = kept
	a.mu.Unlock()
	if !removed {
		return false, nil
	}
	return true, a.save()
}

// List returns the entries for display, sorted so output is stable.
func (a *AuthorizedVaults) List() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.entries))
	for _, e := range a.entries {
		line := base64.StdEncoding.EncodeToString(e.pub)
		if e.label != "" {
			line += " " + e.label
		}
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

// save writes to a temporary file and renames, so an interrupted write cannot
// leave a daemon with a truncated list — which would silently mean "trust the
// next vault that turns up".
func (a *AuthorizedVaults) save() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# ValetFS authorized vault identities.\n")
	b.WriteString("# One base64 X25519 public key per line, optionally followed by a label.\n")
	b.WriteString("# These are public keys, not secrets. Removing a line un-pins that vault.\n")
	b.WriteString("# An EMPTY list means trust-on-first-use: the next vault to connect is pinned.\n")
	for _, e := range a.entries {
		b.WriteString(base64.StdEncoding.EncodeToString(e.pub))
		if e.label != "" {
			b.WriteString(" " + e.label)
		}
		b.WriteString("\n")
	}

	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path)
}

// DefaultLabel names a pinned key by when it was accepted, so a list with
// several entries can be reasoned about later.
func DefaultLabel(now time.Time) string {
	return "pinned-" + now.UTC().Format("2006-01-02")
}
