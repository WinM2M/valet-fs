package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// LegacyDefaultPassphrase is what this program used to fall back to when no
// passphrase was configured. It is published in the source, so every vault
// still encrypted with it is readable by anyone who obtains the directory. It
// survives here for one purpose: opening such a vault long enough to rekey it.
// Never use it to encrypt anything new.
const LegacyDefaultPassphrase = "valetfs-default-dev-passphrase"

// passphraseProvider resolves the vault passphrase. It deliberately has no
// built-in fallback: a default that ships in public source is not a secret.
var passphraseProvider = func() string {
	return os.Getenv("VALETFS_VAULT_PASSWORD")
}

// SetPassphraseProvider overrides passphrase source for vault encryption.
func SetPassphraseProvider(fn func() string) {
	if fn != nil {
		passphraseProvider = fn
	}
}

// manifestMagic opens a manifest written by this version: magic, 16-byte salt,
// then the AES-GCM ciphertext. Keeping the salt next to the ciphertext it
// unlocks is what lets Rekey commit with one atomic rename. Older manifests
// have no magic and keep their salt in salt.bin; they are still read.
var manifestMagic = []byte("VFSM2\n")

const saltLen = 16

// beforeRekeyCommit is a test seam: it runs after every new blob is written and
// before the manifest rename that makes them live.
var beforeRekeyCommit func() error

type Entry struct {
	Path string `json:"path"`
	// BlobSHA names the blob file. Older vaults used the SHA-256 of the
	// plaintext, which let anyone holding the directory test a guess against the
	// file names without the passphrase. New blobs get a random name; the field
	// keeps its old JSON key so existing manifests still load.
	BlobSHA  string    `json:"blob_sha"`
	Size     int64     `json:"size"`
	Mode     uint32    `json:"mode"`
	Modified time.Time `json:"modified"`
}

type Manifest struct {
	Entries map[string]Entry `json:"entries"`
}

type Vault struct {
	Dir string
	mf  Manifest

	// pass is the passphrase actually in force for this handle, resolved once
	// at Open. Resolving per operation would let the effective key change
	// underneath a half-finished rekey.
	pass string
	// legacy records that the vault only opened under LegacyDefaultPassphrase,
	// i.e. its contents are protected by a value anyone can read on GitHub.
	legacy bool
	// unprotected records that the passphrase is empty, so the key is derived
	// from the salt alone and the directory decrypts itself.
	unprotected bool
	// salt is the salt in force for this handle: read from the manifest header,
	// from the legacy salt.bin, or chosen by Rekey before it is committed.
	salt []byte
}

func Open(dir string) (*Vault, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return nil, err
	}
	v := &Vault{Dir: dir, mf: Manifest{Entries: map[string]Entry{}}, pass: passphraseProvider()}
	if err := v.loadManifest(); err != nil {
		// The configured passphrase did not open it. Before giving up, try the
		// passphrase older builds used silently, so an affected vault can still
		// be read and rekeyed instead of being stranded.
		probe := &Vault{Dir: dir, mf: Manifest{Entries: map[string]Entry{}}, pass: LegacyDefaultPassphrase}
		if probe.loadManifest() != nil {
			// "message authentication failed" is what a wrong key looks like at
			// the cipher layer; say what it means instead.
			if v.pass == "" {
				return nil, fmt.Errorf("vault %s: no passphrase given, and the vault is not "+
					"readable without one (set VALETFS_VAULT_PASSWORD or pass --password-file)", dir)
			}
			return nil, fmt.Errorf("vault %s: wrong passphrase", dir)
		}
		probe.legacy = true
		v = probe
	} else if v.pass == LegacyDefaultPassphrase {
		v.legacy = true
	}
	v.unprotected = v.pass == ""
	return v, nil
}

// UsesLegacyPassphrase reports that this vault is encrypted with the passphrase
// published in the source. Callers must warn loudly and steer the user to Rekey.
func (v *Vault) UsesLegacyPassphrase() bool { return v.legacy }

// IsUnprotected reports that no passphrase is in force, so the key derives from
// the stored salt alone and the directory decrypts itself.
func (v *Vault) IsUnprotected() bool { return v.unprotected }

// Rekey re-encrypts every blob and the manifest under a new passphrase and a
// fresh salt. New blobs get new names and the manifest, which now carries the
// salt, is replaced by a single rename. Until that rename the old manifest, salt
// and blobs are untouched, so an interrupted rekey leaves the old vault
// readable rather than half-converted.
func (v *Vault) Rekey(newPass string) error {
	if newPass == "" {
		return fmt.Errorf("rekey: refusing to rekey to an empty passphrase")
	}
	if newPass == LegacyDefaultPassphrase {
		return fmt.Errorf("rekey: that passphrase is published in the source; choose another")
	}

	// Read everything under the current key first.
	plain := make(map[string][]byte, len(v.mf.Entries))
	for path := range v.mf.Entries {
		b, err := v.Read(path)
		if err != nil {
			return fmt.Errorf("rekey: read %s: %w", path, err)
		}
		plain[path] = b
	}

	newSalt := make([]byte, saltLen)
	if _, err := rand.Read(newSalt); err != nil {
		return err
	}
	next := &Vault{Dir: v.Dir, mf: Manifest{Entries: make(map[string]Entry, len(v.mf.Entries))}, pass: newPass, salt: newSalt}

	var written []string
	cleanup := func() {
		for _, id := range written {
			_ = os.Remove(v.blobPath(id))
		}
	}
	for path, body := range plain {
		id, err := newBlobID()
		if err != nil {
			cleanup()
			return err
		}
		enc, err := next.encrypt(body)
		if err != nil {
			cleanup()
			return fmt.Errorf("rekey: encrypt %s: %w", path, err)
		}
		if err := writeFileAtomic(v.blobPath(id), enc, 0o600); err != nil {
			cleanup()
			return fmt.Errorf("rekey: write %s: %w", path, err)
		}
		written = append(written, id)
		e := v.mf.Entries[path]
		e.BlobSHA = id
		next.mf.Entries[path] = e
	}

	if beforeRekeyCommit != nil {
		if err := beforeRekeyCommit(); err != nil {
			cleanup()
			return err
		}
	}
	// Commit point: one rename swaps the manifest and the salt together.
	if err := next.saveManifest(); err != nil {
		cleanup()
		return fmt.Errorf("rekey: commit manifest: %w", err)
	}

	old := v.mf.Entries
	v.pass, v.legacy, v.unprotected, v.salt, v.mf = newPass, false, false, newSalt, next.mf
	// The new generation is live. What is left of the old one is garbage.
	for _, e := range old {
		_ = os.Remove(v.blobPath(e.BlobSHA))
	}
	_ = os.Remove(filepath.Join(v.Dir, "salt.bin"))
	return nil
}

func (v *Vault) Add(hostPath, fsPath string) error {
	b, err := os.ReadFile(hostPath)
	if err != nil {
		return err
	}
	id, err := newBlobID()
	if err != nil {
		return err
	}
	enc, err := v.encrypt(b)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(v.blobPath(id), enc, 0o600); err != nil {
		return err
	}
	st, _ := os.Stat(hostPath)
	p := normalizeFSPath(fsPath)
	prev, had := v.mf.Entries[p]
	v.mf.Entries[p] = Entry{
		Path:     p,
		BlobSHA:  id,
		Size:     int64(len(b)),
		Mode:     uint32(st.Mode().Perm()),
		Modified: time.Now().UTC(),
	}
	if err := v.saveManifest(); err != nil {
		if had {
			v.mf.Entries[p] = prev
		} else {
			delete(v.mf.Entries, p)
		}
		_ = os.Remove(v.blobPath(id))
		return err
	}
	if had {
		v.dropBlobIfUnreferenced(prev.BlobSHA)
	}
	return nil
}

func (v *Vault) Remove(fsPath string) error {
	p := normalizeFSPath(fsPath)
	prev, had := v.mf.Entries[p]
	delete(v.mf.Entries, p)
	if err := v.saveManifest(); err != nil {
		if had {
			v.mf.Entries[p] = prev
		}
		return err
	}
	if had {
		v.dropBlobIfUnreferenced(prev.BlobSHA)
	}
	return nil
}

func (v *Vault) blobPath(id string) string {
	return filepath.Join(v.Dir, "blobs", id+".bin")
}

// dropBlobIfUnreferenced deletes a blob no manifest entry points at. Older
// vaults named blobs by content hash, so two paths with equal content shared one.
func (v *Vault) dropBlobIfUnreferenced(id string) {
	for _, e := range v.mf.Entries {
		if e.BlobSHA == id {
			return
		}
	}
	_ = os.Remove(v.blobPath(id))
}

func newBlobID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// writeFileAtomic writes to a temporary file in the same directory, syncs it,
// then renames it over the target, so a crash leaves the old file or the new
// one and never half of either.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (v *Vault) List(prefix string) []Entry {
	p := normalizeFSPath(prefix)
	out := make([]Entry, 0)
	for k, e := range v.mf.Entries {
		if p == "/" || strings.HasPrefix(k, p) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func (v *Vault) Read(fsPath string) ([]byte, error) {
	e, ok := v.mf.Entries[normalizeFSPath(fsPath)]
	if !ok {
		return nil, fmt.Errorf("not found: %s", fsPath)
	}
	b, err := os.ReadFile(v.blobPath(e.BlobSHA))
	if err != nil {
		return nil, err
	}
	return v.decrypt(b)
}

func (v *Vault) Snapshot() Manifest {
	return v.mf
}

func (v *Vault) loadManifest() error {
	b, err := os.ReadFile(filepath.Join(v.Dir, "manifest.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(b) == 0 {
		return nil
	}
	var plain []byte
	switch {
	case bytes.HasPrefix(b, manifestMagic):
		if len(b) < len(manifestMagic)+saltLen {
			return fmt.Errorf("manifest truncated")
		}
		v.salt = append([]byte(nil), b[len(manifestMagic):len(manifestMagic)+saltLen]...)
		dec, derr := v.decrypt(b[len(manifestMagic)+saltLen:])
		if derr != nil {
			return derr
		}
		plain = dec
	case b[0] == '{' && json.Valid(b):
		// A manifest from before encryption existed. Checking the first byte
		// alone mistook one encrypted manifest in 256 for this, because the
		// first byte of the ciphertext is a random nonce byte.
		plain = b
	default:
		dec, derr := v.decrypt(b)
		if derr != nil {
			return derr
		}
		plain = dec
	}
	if err := json.Unmarshal(plain, &v.mf); err != nil {
		return err
	}
	if v.mf.Entries == nil {
		v.mf.Entries = map[string]Entry{}
	}
	return nil
}

func (v *Vault) saveManifest() error {
	b, err := json.MarshalIndent(v.mf, "", "  ")
	if err != nil {
		return err
	}
	salt, err := v.saltBytes()
	if err != nil {
		return err
	}
	enc, err := v.encrypt(b)
	if err != nil {
		return err
	}
	out := make([]byte, 0, len(manifestMagic)+len(salt)+len(enc))
	out = append(out, manifestMagic...)
	out = append(out, salt...)
	out = append(out, enc...)
	return writeFileAtomic(filepath.Join(v.Dir, "manifest.json"), out, 0o600)
}

func normalizeFSPath(p string) string {
	p = strings.TrimSpace(strings.TrimPrefix(p, "fs:"))
	if p == "" || p == "/" {
		return "/"
	}
	p = strings.TrimPrefix(p, "/")
	return "/" + filepath.ToSlash(p)
}

func CopyTo(dst io.Writer, b []byte) error {
	_, err := dst.Write(b)
	return err
}

func (v *Vault) passphrase() string {
	return v.pass
}

// saltBytes returns the salt for this handle. A vault from before the manifest
// carried its salt keeps it in salt.bin, which is created on first use.
func (v *Vault) saltBytes() ([]byte, error) {
	if v.salt != nil {
		return v.salt, nil
	}
	saltPath := filepath.Join(v.Dir, "salt.bin")
	salt, err := os.ReadFile(saltPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		if err := writeFileAtomic(saltPath, salt, 0o600); err != nil {
			return nil, err
		}
	}
	v.salt = salt
	return salt, nil
}

func (v *Vault) deriveKey() ([]byte, error) {
	salt, err := v.saltBytes()
	if err != nil {
		return nil, err
	}
	return argon2.IDKey([]byte(v.passphrase()), salt, 3, 64*1024, 1, 32), nil
}

func (v *Vault) encrypt(plain []byte) ([]byte, error) {
	key, err := v.deriveKey()
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := gcm.Seal(nonce, nonce, plain, nil)
	return out, nil
}

func (v *Vault) decrypt(enc []byte) ([]byte, error) {
	key, err := v.deriveKey()
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	if len(enc) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, data := enc[:gcm.NonceSize()], enc[gcm.NonceSize():]
	return gcm.Open(nil, nonce, data, nil)
}
