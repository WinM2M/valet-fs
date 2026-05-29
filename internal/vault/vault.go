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

var passphraseProvider = func() string {
	if p := os.Getenv("VALETFS_VAULT_PASSWORD"); p != "" {
		return p
	}
	return "valetfs-default-dev-passphrase"
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
}

func Open(dir string) (*Vault, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return nil, err
	}
	v := &Vault{Dir: dir, mf: Manifest{Entries: map[string]Entry{}}}
	if err := v.loadManifest(); err != nil {
		return nil, err
	}
	return v, nil
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
	return passphraseProvider()
}

func (v *Vault) deriveKey() ([]byte, error) {
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
