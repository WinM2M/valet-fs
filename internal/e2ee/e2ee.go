// Package e2ee adds end-to-end encryption between the vault (controller) and
// the daemon, so the relay hub / Durable Object only ever sees ciphertext.
//
// Handshake (authenticated by the daemon public key delivered out-of-band in
// the pairing QR, or via the session claim for CLI use):
//
//   - daemon generates a static X25519 key pair; its public key travels in the
//     QR / session.
//   - controller generates an ephemeral X25519 key pair, derives the shared
//     secret via X25519, and sends {"kx":"hello","pub":<ctrl pub>} (plaintext —
//     public keys are not secret).
//   - daemon derives the same shared secret from the controller pub.
//   - both HKDF-SHA256 the shared secret into a 32-byte key and use
//     ChaCha20-Poly1305 (12-byte random nonce per message) for every RPC frame,
//     wrapped as {"enc": base64(nonce||ciphertext)}.
//
// Presence frames ({"sys",...}) from the hub stay plaintext and pass through.
package e2ee

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/anomalyco/valet-fs/internal/transport"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const hkdfInfo = "valetfs-e2ee-v1"

// KeyPair is an X25519 key pair.
type KeyPair struct {
	Priv [32]byte
	Pub  [32]byte
}

// Generate creates a fresh X25519 key pair.
func Generate() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := io.ReadFull(rand.Reader, kp.Priv[:]); err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(kp.Priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.Pub[:], pub)
	return kp, nil
}

// PubB64 returns the standard-base64 public key.
func (k *KeyPair) PubB64() string { return base64.StdEncoding.EncodeToString(k.Pub[:]) }

func decodePub(b64 string) ([32]byte, error) {
	var out [32]byte
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, errors.New("e2ee: bad public key length")
	}
	copy(out[:], raw)
	return out, nil
}

func deriveKey(ownPriv [32]byte, peerPub [32]byte) ([]byte, error) {
	shared, err := curve25519.X25519(ownPriv[:], peerPub[:])
	if err != nil {
		return nil, err
	}
	r := hkdf.New(sha256.New, shared, nil, []byte(hkdfInfo))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Session encrypts/decrypts frame payloads with a derived symmetric key.
type Session struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
	}
}

func newSession(key []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Session{aead: aead}, nil
}

func (s *Session) seal(plaintext []byte) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := s.aead.Seal(nil, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ct...)), nil
}

func (s *Session) open(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	ns := s.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("e2ee: ciphertext too short")
	}
	return s.aead.Open(nil, raw[:ns], raw[ns:], nil)
}

type frame struct {
	Sys  string `json:"sys,omitempty"`
	Role string `json:"role,omitempty"`
	KX   string `json:"kx,omitempty"`
	Pub  string `json:"pub,omitempty"`
	Enc  string `json:"enc,omitempty"`
}

// Conn wraps a transport.Conn, transparently encrypting Send and decrypting
// inbound app frames once the handshake completes. Presence frames pass through.
type Conn struct {
	inner        transport.Conn
	kp           *KeyPair
	isController bool

	mu      sync.Mutex
	sess    *Session
	onData  func([]byte)
	onOpen  func()
	onClose func()
}

// WrapController wraps inner for the controller (vault) side. It knows the
// daemon's public key up front and derives the session key immediately.
func WrapController(inner transport.Conn, kp *KeyPair, daemonPubB64 string) (*Conn, error) {
	peer, err := decodePub(daemonPubB64)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(kp.Priv, peer)
	if err != nil {
		return nil, err
	}
	sess, err := newSession(key)
	if err != nil {
		return nil, err
	}
	c := &Conn{inner: inner, kp: kp, isController: true, sess: sess}
	inner.OnData(c.handle)
	return c, nil
}

// WrapDaemon wraps inner for the daemon side. The session key is derived when
// the controller's kx:hello arrives.
func WrapDaemon(inner transport.Conn, kp *KeyPair) *Conn {
	c := &Conn{inner: inner, kp: kp, isController: false}
	inner.OnData(c.handle)
	return c
}

func (c *Conn) handle(b []byte) {
	var f frame
	if err := json.Unmarshal(b, &f); err == nil {
		switch {
		case f.Sys != "":
			c.deliver(b) // presence passes through verbatim
			return
		case f.KX == "hello":
			if !c.isController {
				if peer, err := decodePub(f.Pub); err == nil {
					if key, err := deriveKey(c.kp.Priv, peer); err == nil {
						if sess, err := newSession(key); err == nil {
							c.mu.Lock()
							c.sess = sess
							c.mu.Unlock()
						}
					}
				}
			}
			return
		case f.Enc != "":
			c.mu.Lock()
			sess := c.sess
			c.mu.Unlock()
			if sess == nil {
				return
			}
			if pt, err := sess.open(f.Enc); err == nil {
				c.deliver(pt)
			}
			return
		}
	}
	// Unknown frame: ignore (do not leak).
}

func (c *Conn) deliver(b []byte) {
	c.mu.Lock()
	fn := c.onData
	c.mu.Unlock()
	if fn != nil {
		fn(b)
	}
}

// Start performs the handshake (controller sends kx:hello) and starts the inner
// transport's read loop. inner must expose Start() (the ws transport does).
func (c *Conn) Start() {
	if c.isController {
		f := frame{KX: "hello", Pub: c.kp.PubB64()}
		b, _ := json.Marshal(f)
		_ = c.inner.Send(b)
	}
	if s, ok := c.inner.(interface{ Start() }); ok {
		s.Start()
	}
	c.mu.Lock()
	fn := c.onOpen
	c.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func (c *Conn) OnData(fn func([]byte)) { c.mu.Lock(); c.onData = fn; c.mu.Unlock() }
func (c *Conn) OnOpen(fn func())       { c.mu.Lock(); c.onOpen = fn; c.mu.Unlock() }
func (c *Conn) OnClose(fn func())      { c.mu.Lock(); c.onClose = fn; c.mu.Unlock(); c.inner.OnClose(fn) }

// Send encrypts and transmits an app frame. Fails if the session is not ready.
func (c *Conn) Send(b []byte) error {
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	if sess == nil {
		return errors.New("e2ee: session not established")
	}
	enc, err := sess.seal(b)
	if err != nil {
		return err
	}
	out, _ := json.Marshal(frame{Enc: enc})
	return c.inner.Send(out)
}

func (c *Conn) Close() error { return c.inner.Close() }

// LoadOrGenerate returns the key pair stored at path, creating and persisting a
// fresh one if the file does not exist yet. The second return value reports
// whether an existing key was reused, which callers use to tell a first run
// apart from a restart.
//
// Persisting the daemon's private key is opt-in: it trades a secret at rest for
// a session identity that survives a daemon restart, because the hub pins
// daemon_pub for the lifetime of a session and rejects a different key.
func LoadOrGenerate(path string) (*KeyPair, bool, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, false, fmt.Errorf("key file %s: want 32 bytes, got %d", path, len(b))
		}
		kp := &KeyPair{}
		copy(kp.Priv[:], b)
		pub, err := curve25519.X25519(kp.Priv[:], curve25519.Basepoint)
		if err != nil {
			return nil, false, fmt.Errorf("key file %s: %w", path, err)
		}
		copy(kp.Pub[:], pub)
		return kp, true, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	kp, err := Generate()
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, kp.Priv[:], 0o600); err != nil {
		return nil, false, err
	}
	return kp, false, nil
}
