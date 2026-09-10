package e2ee

import (
	"encoding/json"
	"sync"
	"testing"
)

// fakeConn is a transport.Conn that records what was sent and lets a test push
// inbound frames, standing in for a hub that relays whatever it is given.
type fakeConn struct {
	mu     sync.Mutex
	sent   [][]byte
	onData func([]byte)
}

func (f *fakeConn) OnData(fn func([]byte)) { f.mu.Lock(); f.onData = fn; f.mu.Unlock() }
func (f *fakeConn) OnOpen(func())          {}
func (f *fakeConn) OnClose(func())         {}
func (f *fakeConn) Close() error           { return nil }
func (f *fakeConn) Send(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, append([]byte(nil), b...))
	return nil
}
func (f *fakeConn) push(b []byte) {
	f.mu.Lock()
	fn := f.onData
	f.mu.Unlock()
	if fn != nil {
		fn(b)
	}
}

func hello(t *testing.T, kp *KeyPair) []byte {
	t.Helper()
	b, err := json.Marshal(frame{KX: "hello", Pub: kp.PubB64()})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The daemon's Conn lives as long as its socket to the hub, which outlives many
// app connections, and the app makes a new ephemeral key on every one. Ignoring
// the second hello meant a reconnecting vault kept sending frames the daemon
// could no longer read — silently, and only the first connection after a daemon
// start ever worked.
func TestReconnectingVaultIsAccepted(t *testing.T) {
	daemonKP, _ := Generate()
	first, _ := Generate()
	second, _ := Generate() // a fresh ephemeral, as the app makes on each connect

	inner := &fakeConn{}
	conn := WrapDaemon(inner, daemonKP)
	var got [][]byte
	conn.OnData(func(b []byte) { got = append(got, append([]byte(nil), b...)) })

	inner.push(hello(t, first))
	inner.push(hello(t, second))
	if conn.Rekeys() != 1 {
		t.Fatalf("the reconnect should be counted once, got %d", conn.Rekeys())
	}

	// Traffic under the NEW key must arrive: that is what reconnecting means.
	key, _ := deriveKey(second.Priv, daemonKP.Pub)
	sess, _ := newSession(key)
	ct, _ := sess.seal([]byte(`{"type":"REQ","method":"STATUS"}`))
	blob, _ := json.Marshal(frame{Enc: ct})
	inner.push(blob)
	if len(got) != 1 || string(got[0]) != `{"type":"REQ","method":"STATUS"}` {
		t.Fatalf("the reconnected vault could not be heard: %q", got)
	}

	// And the old key is finished, which is what a rekey means.
	oldKey, _ := deriveKey(first.Priv, daemonKP.Pub)
	oldSess, _ := newSession(oldKey)
	ct, _ = oldSess.seal([]byte(`{"type":"REQ","method":"PULL"}`))
	blob, _ = json.Marshal(frame{Enc: ct})
	inner.push(blob)
	if len(got) != 1 {
		t.Fatal("a frame under the superseded key was still accepted")
	}
}

// What keeps strangers out of the vault role in v1 is the claim secret, not
// this layer: v1 cannot tell a legitimate reconnect from a takeover, because on
// the wire they are the same thing. That is the hole v2 exists to close, and
// this test records the limit rather than pretending it is covered.
func TestV1CannotDistinguishReconnectFromTakeover(t *testing.T) {
	daemonKP, _ := Generate()
	legit, _ := Generate()
	stranger, _ := Generate()

	inner := &fakeConn{}
	conn := WrapDaemon(inner, daemonKP)
	var got [][]byte
	conn.OnData(func(b []byte) { got = append(got, append([]byte(nil), b...)) })

	inner.push(hello(t, legit))
	inner.push(hello(t, stranger))

	key, _ := deriveKey(stranger.Priv, daemonKP.Pub)
	sess, _ := newSession(key)
	ct, _ := sess.seal([]byte(`{"type":"REQ","method":"PULL"}`))
	blob, _ := json.Marshal(frame{Enc: ct})
	inner.push(blob)
	if len(got) != 1 {
		t.Fatal("v1 is expected to accept this; if it no longer does, the comment above is stale")
	}
}

// A brand new Conn, as a daemon restart produces, must also handshake cleanly.
func TestReconnectGetsAFreshHandshake(t *testing.T) {
	daemonKP, _ := Generate()
	peerKP, _ := Generate()

	inner := &fakeConn{}
	conn := WrapDaemon(inner, daemonKP)
	inner.push(hello(t, peerKP))
	if conn.Rekeys() != 0 {
		t.Fatal("the first handshake is not a rekey")
	}

	reconnected := WrapDaemon(&fakeConn{}, daemonKP)
	var delivered [][]byte
	reconnected.OnData(func(b []byte) { delivered = append(delivered, b) })
	inner2 := reconnected.inner.(*fakeConn)
	inner2.push(hello(t, peerKP))

	key, _ := deriveKey(peerKP.Priv, daemonKP.Pub)
	sess, _ := newSession(key)
	ct, _ := sess.seal([]byte(`{"type":"REQ","method":"STATUS"}`))
	blob, _ := json.Marshal(frame{Enc: ct})
	inner2.push(blob)
	if len(delivered) != 1 {
		t.Fatal("a reconnected daemon must complete a fresh handshake")
	}
}
