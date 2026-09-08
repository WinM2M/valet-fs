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

// A daemon used to accept a kx:hello at any moment and swap the session key for
// it, so anyone who reached the session could seize the channel mid-conversation
// and then read the whole vault. Only the first handshake counts.
func TestDaemonRefusesToRekeyMidSession(t *testing.T) {
	daemonKP, _ := Generate()
	legitKP, _ := Generate()
	attackerKP, _ := Generate()

	inner := &fakeConn{}
	conn := WrapDaemon(inner, daemonKP)

	var got [][]byte
	conn.OnData(func(b []byte) { got = append(got, append([]byte(nil), b...)) })

	inner.push(hello(t, legitKP))

	// The attacker joins the session and tries to take the channel over.
	inner.push(hello(t, attackerKP))
	if conn.RekeyAttempts() != 1 {
		t.Fatalf("rekey attempt not recorded: got %d", conn.RekeyAttempts())
	}

	// The legitimate peer's traffic still decrypts...
	legitKey, _ := deriveKey(legitKP.Priv, daemonKP.Pub)
	legitSess, _ := newSession(legitKey)
	ct, _ := legitSess.seal([]byte(`{"type":"REQ","method":"STATUS"}`))
	blob, _ := json.Marshal(frame{Enc: ct})
	inner.push(blob)
	if len(got) != 1 || string(got[0]) != `{"type":"REQ","method":"STATUS"}` {
		t.Fatalf("legitimate peer lost the channel: %q", got)
	}

	// ...and the attacker's does not.
	attackerKey, _ := deriveKey(attackerKP.Priv, daemonKP.Pub)
	attackerSess, _ := newSession(attackerKey)
	ct, _ = attackerSess.seal([]byte(`{"type":"REQ","method":"PULL"}`))
	blob, _ = json.Marshal(frame{Enc: ct})
	inner.push(blob)
	if len(got) != 1 {
		t.Fatalf("attacker frame was decrypted and delivered: %q", got)
	}
}

// A reconnect builds a fresh Conn, which must still be able to handshake.
func TestReconnectGetsAFreshHandshake(t *testing.T) {
	daemonKP, _ := Generate()
	peerKP, _ := Generate()

	inner := &fakeConn{}
	conn := WrapDaemon(inner, daemonKP)
	inner.push(hello(t, peerKP))
	if conn.RekeyAttempts() != 0 {
		t.Fatal("first handshake must not count as a rekey attempt")
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
