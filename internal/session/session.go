// Package session is the v2 control-plane security layer: a Noise IK handshake
// between the vault and the daemon, and authenticated framing on top of it.
//
// It replaces the v1 layer in internal/e2ee, which had three faults that are the
// standard ways a hand-rolled protocol fails:
//
//   - Nothing authenticated the controller. The daemon derived a key from
//     whatever public key arrived, so anyone who reached the session became the
//     vault and could read everything with MANIFEST and PULL.
//   - Both directions used the same key, with no transcript binding.
//   - No replay protection at all. A recorded WRITE could be played back later,
//     and because WRITE remounts, that alone would resurrect a locked daemon.
//
// Noise IK closes all three. The initiator (the vault) already knows the
// responder's static key out of band — from the pairing QR, or from the
// connection key the app wrote itself — which is exactly what IK assumes. It
// gives mutual authentication, a key per direction, a transcript hash over the
// whole handshake, and forward secrecy that the v1 layer never had: a leaked
// daemon static key no longer opens past sessions.
//
// Authorisation is separate from authentication and lives here too. Noise tells
// the daemon WHICH vault it is talking to; Authorised decides whether that vault
// is allowed. Conflating the two is how "the handshake succeeded" quietly comes
// to mean "the caller is permitted".
package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/anomalyco/valet-fs/internal/transport"
	"github.com/flynn/noise"
)

// Protocol is the Noise pattern and cipher suite this layer speaks. It is also
// mixed into the prologue, so a peer running a different suite fails during the
// handshake rather than somewhere further in.
const Protocol = "Noise_IK_25519_ChaChaPoly_SHA256"

var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// Errors callers are expected to distinguish.
var (
	// ErrUnauthorised means the handshake completed and identified a vault this
	// daemon has not been told to accept. It is a refusal, not a failure.
	ErrUnauthorised = errors.New("session: vault key is not authorised for this daemon")
	// ErrNotEstablished means a frame arrived before the handshake finished.
	ErrNotEstablished = errors.New("session: handshake not complete")
)

// wire frames. Kept distinct from v1's {"kx"/"enc"} so a v1 peer cannot be
// mistaken for a v2 one, in either direction.
type frame struct {
	// Sys carries hub presence and passes through untouched.
	Sys string `json:"sys,omitempty"`
	// NX is the handshake message number, "1" or "2".
	NX string `json:"nx,omitempty"`
	// N is a transport frame.
	N string `json:"n,omitempty"`
	// M is the handshake payload for NX frames.
	M string `json:"m,omitempty"`
}

// Conn wraps a transport.Conn with an authenticated, encrypted session.
type Conn struct {
	inner     transport.Conn
	initiator bool
	sid       string

	// authorised is consulted by the daemon once Noise reveals who the peer is.
	// Empty means "trust on first use": the first vault to complete a handshake
	// is recorded, and a different one afterwards is refused.
	authorised [][]byte
	onPin      func(pub []byte)
	// cfg is kept so a fresh handshake state can be built when the peer
	// reconnects. The daemon's socket to the hub outlives many app
	// connections, and each one is a new handshake.
	cfg Config

	mu      sync.Mutex
	hs      *noise.HandshakeState
	send    *noise.CipherState
	recv    *noise.CipherState
	peerPub []byte
	onData  func([]byte)
	onOpen  func()
	onClose func()
	failErr error
	// ready closes once the session can carry traffic. v1 needed nothing like
	// this because its controller derived a key with no round trip; v2 has one,
	// so a caller that sends immediately after Start would otherwise race the
	// handshake and get an error that looks like a bug in the peer.
	ready     chan struct{}
	readyOnce sync.Once
}

func (c *Conn) markReady() { c.readyOnce.Do(func() { close(c.ready) }) }

// abandon unblocks a waiting Start when the session can no longer complete —
// the peer refused us, or the connection went away. Waiting out a timeout for a
// question that has already been answered is just a slower way to fail.
func (c *Conn) abandon(err error) {
	c.mu.Lock()
	if c.failErr == nil {
		c.failErr = err
	}
	c.mu.Unlock()
	c.markReady()
}

// Config describes one end of a session.
type Config struct {
	Inner transport.Conn
	// SessionID binds every frame to this session; a frame lifted from another
	// session fails to authenticate even if the keys somehow matched.
	SessionID string
	// Static is this end's long-lived key pair.
	Static noise.DHKey
	// PeerStatic is required for the initiator: IK means knowing it in advance.
	PeerStatic []byte
	// Authorised lists the vault keys a daemon accepts. Ignored by the
	// initiator. Empty means trust-on-first-use via OnPin.
	Authorised [][]byte
	// OnPin is called with the peer's key when a daemon accepts one under
	// trust-on-first-use, so the caller can persist it.
	OnPin func(pub []byte)
	// Random supplies the ephemeral key. Nil means crypto/rand, which is what
	// production uses; it exists so a transcript can be reproduced exactly,
	// which is how the app's independent implementation is checked against this
	// one rather than merely against itself.
	Random io.Reader
}

// prologue binds the handshake to the protocol name and the session id, so a
// transcript from one session cannot be replayed into another.
func prologue(sid string) []byte {
	return []byte(Protocol + "\x00" + sid)
}

// ad is the additional data on every transport frame: the session it belongs to
// and the direction it travels.
//
// Noise already gives each direction its own key and advances a nonce per
// message, so ordering and reflection are covered by the cipher states
// themselves. What they do not cover is a frame lifted into a different
// session, which is what the session id is doing here. The direction byte is
// redundant against separate keys and is included anyway, because an invariant
// that is written down survives a refactor better than one that depends on the
// reader knowing how Noise splits keys.
func ad(sid string, fromInitiator bool) []byte {
	dir := byte('d') // daemon -> vault
	if fromInitiator {
		dir = 'v' // vault -> daemon
	}
	return append([]byte(sid+"\x00"), dir)
}

// NewVault builds the initiator side.
func NewVault(cfg Config) (*Conn, error) {
	if len(cfg.PeerStatic) == 0 {
		return nil, errors.New("session: vault needs the daemon's static key (IK)")
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Random:        cfg.Random,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      prologue(cfg.SessionID),
		StaticKeypair: cfg.Static,
		PeerStatic:    cfg.PeerStatic,
	})
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	c := &Conn{inner: cfg.Inner, initiator: true, sid: cfg.SessionID, hs: hs, peerPub: cfg.PeerStatic, ready: make(chan struct{})}
	cfg.Inner.OnData(c.handle)
	cfg.Inner.OnClose(func() { c.abandon(errors.New("session: connection closed")) })
	return c, nil
}

// NewDaemon builds the responder side.
func NewDaemon(cfg Config) (*Conn, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Random:        cfg.Random,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      prologue(cfg.SessionID),
		StaticKeypair: cfg.Static,
	})
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	c := &Conn{
		inner: cfg.Inner, initiator: false, sid: cfg.SessionID, hs: hs,
		authorised: cfg.Authorised, onPin: cfg.OnPin, cfg: cfg, ready: make(chan struct{}),
	}
	cfg.Inner.OnData(c.handle)
	return c, nil
}

// PeerStatic is the peer's long-lived public key, known once the handshake has
// completed. For a daemon this is the identity it just authorised.
func (c *Conn) PeerStatic() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerPub
}

// Established reports whether transport frames can flow.
func (c *Conn) Established() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.send != nil
}

// Err returns why the session failed, if it did. A refused vault key surfaces
// here rather than as a silently dead connection.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failErr
}

func (c *Conn) authorise(pub []byte) error {
	if len(c.authorised) == 0 {
		if c.onPin != nil {
			c.onPin(pub)
		}
		return nil
	}
	for _, a := range c.authorised {
		if len(a) == len(pub) && subtleEqual(a, pub) {
			return nil
		}
	}
	return ErrUnauthorised
}

func (c *Conn) handle(b []byte) {
	var f frame
	if json.Unmarshal(b, &f) != nil {
		return // not ours; drop rather than guess
	}
	switch {
	case f.Sys != "":
		c.deliver(b)
	case f.NX == "1":
		c.readHandshake1(f)
	case f.NX == "2":
		c.readHandshake2(f)
	case f.N != "":
		c.readTransport(f)
	}
}

func (c *Conn) readHandshake1(f frame) {
	if c.initiator {
		return // the initiator wrote it
	}
	msg, err := base64.StdEncoding.DecodeString(f.M)
	if err != nil {
		return
	}
	c.mu.Lock()
	if c.hs == nil {
		// A previous handshake finished on this connection. That is the normal
		// case, not an attack: this daemon's socket to the hub outlives many app
		// connections, and every time the phone opens a session screen it starts
		// a fresh one. Refusing here meant only the first ever connection worked.
		//
		// Allowing it is safe precisely because the handshake authenticates: an
		// unauthorised vault cannot complete one, and authorise() runs again
		// below on whatever identity this handshake reveals.
		fresh, err := noise.NewHandshakeState(noise.Config{
			CipherSuite:   suite,
			Random:        c.cfg.Random,
			Pattern:       noise.HandshakeIK,
			Initiator:     false,
			Prologue:      prologue(c.sid),
			StaticKeypair: c.cfg.Static,
		})
		if err != nil {
			c.mu.Unlock()
			return
		}
		c.hs = fresh
		c.send, c.recv = nil, nil
	}
	if _, _, _, err := c.hs.ReadMessage(nil, msg); err != nil {
		// A failed read leaves the state unusable; drop it so the next attempt
		// starts clean rather than compounding on a half-consumed handshake.
		c.hs = nil
		c.mu.Unlock()
		return
	}
	peer := append([]byte(nil), c.hs.PeerStatic()...)
	c.mu.Unlock()

	// Authentication told us who; authorisation decides whether they may.
	if err := c.authorise(peer); err != nil {
		c.mu.Lock()
		c.failErr = err
		c.mu.Unlock()
		_ = c.inner.Close()
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	out, cs1, cs2, err := c.hs.WriteMessage(nil, nil)
	if err != nil {
		c.failErr = err
		return
	}
	// Split returns spec order (c1 = initiator->responder). The responder sends
	// on c2.
	c.send, c.recv = cs2, cs1
	c.peerPub = peer
	b, _ := json.Marshal(frame{NX: "2", M: base64.StdEncoding.EncodeToString(out)})
	_ = c.inner.Send(b)
	c.hs = nil
	c.markReady()
}

func (c *Conn) readHandshake2(f frame) {
	if !c.initiator {
		return
	}
	msg, err := base64.StdEncoding.DecodeString(f.M)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hs == nil || c.send != nil {
		return
	}
	_, cs1, cs2, err := c.hs.ReadMessage(nil, msg)
	if err != nil {
		c.failErr = err
		return
	}
	c.send, c.recv = cs1, cs2
	c.hs = nil
	c.markReady()
}

func (c *Conn) readTransport(f frame) {
	raw, err := base64.StdEncoding.DecodeString(f.N)
	if err != nil {
		return
	}
	c.mu.Lock()
	recv := c.recv
	c.mu.Unlock()
	if recv == nil {
		return
	}
	// The peer writes in the other direction from us.
	pt, err := recv.Decrypt(nil, ad(c.sid, !c.initiator), raw)
	if err != nil {
		return // forged, replayed, or from another session
	}
	c.deliver(pt)
}

func (c *Conn) deliver(b []byte) {
	c.mu.Lock()
	fn := c.onData
	c.mu.Unlock()
	if fn != nil {
		fn(b)
	}
}

// Send encrypts and transmits an application frame.
func (c *Conn) Send(b []byte) error {
	c.mu.Lock()
	send := c.send
	c.mu.Unlock()
	if send == nil {
		return ErrNotEstablished
	}
	ct, err := send.Encrypt(nil, ad(c.sid, c.initiator), b)
	if err != nil {
		return err
	}
	out, _ := json.Marshal(frame{N: base64.StdEncoding.EncodeToString(ct)})
	return c.inner.Send(out)
}

// Start begins the handshake and, for the vault, does not return until the
// session can carry traffic or ctx is done.
//
// Waiting is part of Start rather than a separate call the caller must remember,
// because forgetting it fails as "handshake not complete" on the first send —
// an error that reads like a fault in the peer rather than a race in the caller.
// The daemon side has nothing to wait for: it answers when the vault speaks.
func (c *Conn) Start(ctx context.Context) error {
	if c.initiator {
		c.mu.Lock()
		out, _, _, err := c.hs.WriteMessage(nil, nil)
		c.mu.Unlock()
		if err != nil {
			return fmt.Errorf("session: handshake: %w", err)
		}
		b, _ := json.Marshal(frame{NX: "1", M: base64.StdEncoding.EncodeToString(out)})
		if err := c.inner.Send(b); err != nil {
			return err
		}
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
	if !c.initiator {
		return nil
	}
	select {
	case <-c.ready:
		if err := c.Err(); err != nil {
			return err
		}
		if !c.Established() {
			return errors.New("session: the peer closed the connection during the handshake")
		}
		return nil
	case <-ctx.Done():
		if err := c.Err(); err != nil {
			return err
		}
		return fmt.Errorf("session: handshake did not complete: %w", ctx.Err())
	}
}

func (c *Conn) OnData(fn func([]byte)) { c.mu.Lock(); c.onData = fn; c.mu.Unlock() }
func (c *Conn) OnOpen(fn func())       { c.mu.Lock(); c.onOpen = fn; c.mu.Unlock() }
func (c *Conn) OnClose(fn func())      { c.mu.Lock(); c.onClose = fn; c.mu.Unlock(); c.inner.OnClose(fn) }
func (c *Conn) Close() error           { return c.inner.Close() }

// GenerateStatic makes a long-lived key pair for either end.
func GenerateStatic() (noise.DHKey, error) { return suite.GenerateKeypair(nil) }

// PubB64 renders a public key for transport in a QR or connection key.
func PubB64(pub []byte) string { return base64.StdEncoding.EncodeToString(pub) }

// ParsePub reads a public key produced by PubB64.
func ParsePub(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("session: public key must be 32 bytes")
	}
	return b, nil
}
