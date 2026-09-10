package session

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
)

// pipe is a pair of in-memory transports wired to each other.
type pipe struct {
	mu     sync.Mutex
	peer   *pipe
	onData func([]byte)
	sent   [][]byte
	closed bool
	drop   bool // when set, swallow instead of delivering
}

func newPipe() (*pipe, *pipe) {
	a, b := &pipe{}, &pipe{}
	a.peer, b.peer = b, a
	return a, b
}

func (p *pipe) OnData(f func([]byte)) { p.mu.Lock(); p.onData = f; p.mu.Unlock() }
func (p *pipe) OnOpen(func())         {}
func (p *pipe) OnClose(func())        {}
func (p *pipe) Close() error          { p.mu.Lock(); p.closed = true; p.mu.Unlock(); return nil }
func (p *pipe) Send(b []byte) error {
	cp := append([]byte(nil), b...)
	p.mu.Lock()
	p.sent = append(p.sent, cp)
	drop := p.drop
	p.mu.Unlock()
	if drop {
		return nil
	}
	p.peer.mu.Lock()
	fn := p.peer.onData
	p.peer.mu.Unlock()
	if fn != nil {
		fn(cp)
	}
	return nil
}
func (p *pipe) isClosed() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.closed }
func (p *pipe) lastSent() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.sent) == 0 {
		return nil
	}
	return p.sent[len(p.sent)-1]
}

func mustKey(t *testing.T) noise.DHKey {
	t.Helper()
	k, err := GenerateStatic()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// establish wires a vault and a daemon over a pipe and completes the handshake.
func establish(t *testing.T, sid string, vaultKey, daemonKey noise.DHKey, authorised [][]byte) (*Conn, *Conn, *pipe, *pipe) {
	t.Helper()
	vp, dp := newPipe()
	v, err := NewVault(Config{Inner: vp, SessionID: sid, Static: vaultKey, PeerStatic: daemonKey.Public})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	d, err := NewDaemon(Config{Inner: dp, SessionID: sid, Static: daemonKey, Authorised: authorised})
	if err != nil {
		t.Fatalf("daemon: %v", err)
	}
	// A bounded context: a refused vault never gets a reply, and a helper that
	// waits forever turns a refusal into a hung test rather than a failed one.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// The error is the assertion's business, not the helper's: several tests
	// here exist precisely because the handshake should not succeed.
	_ = v.Start(ctx)
	return v, d, vp, dp
}

func TestAuthorisedVaultCompletesAndTalksBothWays(t *testing.T) {
	vk, dk := mustKey(t), mustKey(t)
	v, d, _, _ := establish(t, "sid-1", vk, dk, [][]byte{vk.Public})

	if !v.Established() || !d.Established() {
		t.Fatal("handshake did not complete")
	}
	// The daemon must know exactly who it accepted.
	if !subtleEqual(d.PeerStatic(), vk.Public) {
		t.Fatal("daemon did not learn the vault's identity")
	}

	var toDaemon, toVault [][]byte
	d.OnData(func(b []byte) { toDaemon = append(toDaemon, append([]byte(nil), b...)) })
	v.OnData(func(b []byte) { toVault = append(toVault, append([]byte(nil), b...)) })

	if err := v.Send([]byte(`{"type":"REQ","method":"STATUS"}`)); err != nil {
		t.Fatalf("vault send: %v", err)
	}
	if err := d.Send([]byte(`{"type":"RES","ok":true}`)); err != nil {
		t.Fatalf("daemon send: %v", err)
	}
	if len(toDaemon) != 1 || string(toDaemon[0]) != `{"type":"REQ","method":"STATUS"}` {
		t.Fatalf("daemon did not receive the request: %q", toDaemon)
	}
	if len(toVault) != 1 || string(toVault[0]) != `{"type":"RES","ok":true}` {
		t.Fatalf("vault did not receive the response: %q", toVault)
	}
}

// The v1 fault: anyone who reached the session became the vault. Authentication
// now identifies the peer, and authorisation decides separately whether it may.
func TestUnauthorisedVaultIsRefused(t *testing.T) {
	authorised, attacker, dk := mustKey(t), mustKey(t), mustKey(t)
	v, d, _, dp := establish(t, "sid-1", attacker, dk, [][]byte{authorised.Public})

	if d.Established() {
		t.Fatal("daemon completed a session with an unauthorised vault")
	}
	if !errors.Is(d.Err(), ErrUnauthorised) {
		t.Fatalf("want ErrUnauthorised, got %v", d.Err())
	}
	if !dp.isClosed() {
		t.Fatal("the connection should be closed on refusal, not left half-open")
	}
	// And the attacker cannot push anything through regardless.
	if err := v.Send([]byte(`{"type":"REQ","method":"PULL"}`)); err == nil {
		t.Fatal("an unauthorised vault must not be able to send")
	}
}

// With no authorised list the daemon trusts the first vault it meets, and
// records it, so a different one afterwards is a different question.
func TestTrustOnFirstUseReportsThePinnedKey(t *testing.T) {
	vk, dk := mustKey(t), mustKey(t)
	var pinned []byte
	vp, dp := newPipe()
	v, _ := NewVault(Config{Inner: vp, SessionID: "sid-1", Static: vk, PeerStatic: dk.Public})
	d, _ := NewDaemon(Config{
		Inner: dp, SessionID: "sid-1", Static: dk,
		OnPin: func(pub []byte) { pinned = append([]byte(nil), pub...) },
	})
	if err := v.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !d.Established() {
		t.Fatal("first vault should be accepted")
	}
	if !subtleEqual(pinned, vk.Public) {
		t.Fatal("the accepted key was not reported for pinning")
	}
}

// A frame is bound to its session, so one lifted from another cannot be
// replayed even though both ends hold real keys.
func TestFrameFromAnotherSessionIsRejected(t *testing.T) {
	vk, dk := mustKey(t), mustKey(t)

	// A genuine vault->daemon frame, captured from session A.
	vA, _, vpA, _ := establish(t, "session-A", vk, dk, [][]byte{vk.Public})
	if err := vA.Send([]byte(`{"type":"REQ","method":"PULL"}`)); err != nil {
		t.Fatal(err)
	}
	stolen := vpA.lastSent()
	if stolen == nil {
		t.Fatal("no frame captured")
	}

	// The same keys, a different session. Without the session id in the
	// additional data this would decrypt, because both ends are real.
	_, dB, vpB, _ := establish(t, "session-B", vk, dk, [][]byte{vk.Public})
	var got [][]byte
	dB.OnData(func(b []byte) { got = append(got, b) })
	if err := vpB.Send(stolen); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("a frame from another session was accepted")
	}
}

// Replaying a frame back into the session it came from must also fail: the
// receiving cipher state has already moved past that nonce.
func TestReplayWithinTheSameSessionIsRejected(t *testing.T) {
	vk, dk := mustKey(t), mustKey(t)
	v, d, vp, _ := establish(t, "sid-1", vk, dk, [][]byte{vk.Public})

	var got [][]byte
	d.OnData(func(b []byte) { got = append(got, append([]byte(nil), b...)) })

	if err := v.Send([]byte(`{"type":"REQ","method":"WRITE"}`)); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("first delivery failed: %d", len(got))
	}
	replayed := vp.lastSent()
	_ = vp.Send(replayed)
	if len(got) != 1 {
		t.Fatal("a replayed frame was delivered a second time")
	}
}

// Reflecting a daemon frame back at the daemon must fail: each direction has
// its own key, and the frame is bound to a direction as well.
func TestReflectedFrameIsRejected(t *testing.T) {
	vk, dk := mustKey(t), mustKey(t)
	_, d, _, dp := establish(t, "sid-1", vk, dk, [][]byte{vk.Public})

	if err := d.Send([]byte(`{"type":"RES","ok":true}`)); err != nil {
		t.Fatal(err)
	}
	reflected := dp.lastSent()

	var got [][]byte
	d.OnData(func(b []byte) { got = append(got, b) })
	_ = dp.Send(reflected)
	if len(got) != 0 {
		t.Fatal("the daemon accepted its own frame reflected back")
	}
}

// A second handshake attempt after the session is up must not take it over.
func TestSecondHandshakeIsIgnored(t *testing.T) {
	vk, dk, attacker := mustKey(t), mustKey(t), mustKey(t)
	_, d, _, dp := establish(t, "sid-1", vk, dk, [][]byte{vk.Public, attacker.Public})
	before := d.PeerStatic()

	// Build a fresh, valid message 1 from the attacker and inject it.
	ap, _ := newPipe()
	av, err := NewVault(Config{Inner: ap, SessionID: "sid-1", Static: attacker, PeerStatic: dk.Public})
	if err != nil {
		t.Fatal(err)
	}
	// Nothing answers this pipe, so the handshake never completes; the point is
	// only to obtain a well-formed message 1 to inject below.
	actx, acancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer acancel()
	_ = av.Start(actx)
	var f frame
	if err := json.Unmarshal(ap.lastSent(), &f); err != nil {
		t.Fatal(err)
	}
	inject, _ := json.Marshal(frame{NX: "1", M: f.M})
	_ = dp.peer.Send(inject)

	if !subtleEqual(d.PeerStatic(), before) {
		t.Fatal("a second handshake replaced the established peer identity")
	}
}

func shortCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Second)
}

// keyFromPrivate rebuilds a key pair from a fixed private scalar, for
// reproducible transcripts.
func keyFromPrivate(priv []byte) (noise.DHKey, error) {
	pub, err := suite.DH(priv, basepoint())
	if err != nil {
		return noise.DHKey{}, err
	}
	return noise.DHKey{Private: append([]byte(nil), priv...), Public: pub}, nil
}
