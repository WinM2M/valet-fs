package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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

type Entry struct {
	Path     string    `json:"path"`
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
	// saltOverride lets Rekey encrypt under a new salt before that salt is
	// committed to disk.
	saltOverride []byte
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
// fresh salt. It writes the new blobs before swapping the salt, so an
// interrupted rekey leaves the old vault readable rather than half-converted.
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

	newSalt := make([]byte, 16)
	if _, err := rand.Read(newSalt); err != nil {
		return err
	}
	next := &Vault{Dir: v.Dir, mf: v.mf, pass: newPass, saltOverride: newSalt}

	for path, body := range plain {
		e := v.mf.Entries[path]
		enc, err := next.encrypt(body)
		if err != nil {
			return fmt.Errorf("rekey: encrypt %s: %w", path, err)
		}
		if err := os.WriteFile(filepath.Join(v.Dir, "blobs", e.BlobSHA+".bin"), enc, 0o600); err != nil {
			return fmt.Errorf("rekey: write %s: %w", path, err)
		}
	}

	// Commit: the salt is what makes the new blobs readable, so it lands last.
	if err := os.WriteFile(filepath.Join(v.Dir, "salt.bin"), newSalt, 0o600); err != nil {
		return fmt.Errorf("rekey: write salt: %w", err)
	}
	v.pass, v.legacy, v.unprotected, v.saltOverride = newPass, false, false, newSalt
	return v.saveManifest()
}

func (v *Vault) Add(hostPath, fsPath string) error {
	b, err := os.ReadFile(hostPath)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	sha := hex.EncodeToString(h[:])
	enc, err := v.encrypt(b)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(v.Dir, "blobs", sha+".bin"), enc, 0o600); err != nil {
		return err
	}
	st, _ := os.Stat(hostPath)
	p := normalizeFSPath(fsPath)
	v.mf.Entries[p] = Entry{
		Path:     p,
		BlobSHA:  sha,
		Size:     int64(len(b)),
		Mode:     uint32(st.Mode().Perm()),
		Modified: time.Now().UTC(),
	}
	return v.saveManifest()
}

func (v *Vault) Remove(fsPath string) error {
	p := normalizeFSPath(fsPath)
	delete(v.mf.Entries, p)
	return v.saveManifest()
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
	b, err := os.ReadFile(filepath.Join(v.Dir, "blobs", e.BlobSHA+".bin"))
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
	plain := b
	if len(b) > 0 && b[0] != '{' {
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
	enc, err := v.encrypt(b)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(v.Dir, "manifest.json"), enc, 0o600)
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

func (v *Vault) deriveKey() ([]byte, error) {
	if v.saltOverride != nil {
		return argon2.IDKey([]byte(v.passphrase()), v.saltOverride, 3, 64*1024, 1, 32), nil
	}
	saltPath := filepath.Join(v.Dir, "salt.bin")
	salt, err := os.ReadFile(saltPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		if err := os.WriteFile(saltPath, salt, 0o600); err != nil {
			return nil, err
		}
	}
	key := argon2.IDKey([]byte(v.passphrase()), salt, 3, 64*1024, 1, 32)
	return key, nil
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
