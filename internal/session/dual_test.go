package session

import (
	"encoding/json"
	"testing"

	"github.com/anomalyco/valet-fs/internal/e2ee"
)

// A v2 vault gets v2, and the frame that chose the version is not lost on the
// way. Losing it would leave the handshake stalled with nothing in the logs.
func TestDualServesV2AndKeepsTheFirstFrame(t *testing.T) {
	vk, dk := mustKey(t), mustKey(t)
	vp, dp := newPipe()

	var chose int
	d := NewDual(DualConfig{
		Inner:    dp,
		V2:       Config{SessionID: "sid-1", Static: dk, Authorised: [][]byte{vk.Public}},
		OnChoose: func(v int) { chose = v },
	})
	var got [][]byte
	d.OnData(func(b []byte) { got = append(got, append([]byte(nil), b...)) })

	v, err := NewVault(Config{Inner: vp, SessionID: "sid-1", Static: vk, PeerStatic: dk.Public})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(); err != nil {
		t.Fatal(err)
	}

	if chose != 2 || d.Version() != 2 {
		t.Fatalf("want v2, chose=%d version=%d", chose, d.Version())
	}
	if !v.Established() {
		t.Fatal("the handshake did not complete, so the selecting frame was dropped")
	}
	if err := v.Send([]byte(`{"type":"REQ","method":"STATUS"}`)); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(got) != 1 || string(got[0]) != `{"type":"REQ","method":"STATUS"}` {
		t.Fatalf("payload did not arrive: %q", got)
	}
}

// The App Store build speaks v1, and must keep working until M3 retires it.
func TestDualStillServesV1(t *testing.T) {
	dkV1, err := e2ee.Generate()
	if err != nil {
		t.Fatal(err)
	}
	vkV1, err := e2ee.Generate()
	if err != nil {
		t.Fatal(err)
	}
	vp, dp := newPipe()

	var chose int
	d := NewDual(DualConfig{
		Inner:    dp,
		V1Static: dkV1,
		V2:       Config{SessionID: "sid-1", Static: mustKey(t)},
		OnChoose: func(v int) { chose = v },
	})
	var got [][]byte
	d.OnData(func(b []byte) { got = append(got, append([]byte(nil), b...)) })

	v1, err := e2ee.WrapController(vp, vkV1, dkV1.PubB64())
	if err != nil {
		t.Fatal(err)
	}
	v1.Start()

	if chose != 1 || d.Version() != 1 {
		t.Fatalf("want v1, chose=%d version=%d", chose, d.Version())
	}
	if err := v1.Send([]byte(`{"type":"REQ","method":"STATUS"}`)); err != nil {
		t.Fatalf("v1 send: %v", err)
	}
	if len(got) != 1 || string(got[0]) != `{"type":"REQ","method":"STATUS"}` {
		t.Fatalf("v1 payload did not arrive: %q", got)
	}
}

// Presence has to reach the node before any version is settled: peer_offline is
// what arms the grace timer, and a daemon nobody ever claims must still lock.
func TestDualPassesPresenceBeforeAnyHandshake(t *testing.T) {
	vp, dp := newPipe()
	d := NewDual(DualConfig{Inner: dp, V2: Config{SessionID: "sid-1", Static: mustKey(t)}})
	var got [][]byte
	d.OnData(func(b []byte) { got = append(got, append([]byte(nil), b...)) })

	frame, _ := json.Marshal(map[string]string{"sys": "peer_offline", "role": "vault"})
	if err := vp.Send(frame); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatal("presence must pass through before a version is chosen")
	}
	if d.Version() != 0 {
		t.Fatal("presence must not select a version")
	}
}

// Once chosen, the version is fixed. Letting a later frame switch it would hand
// an attacker a way to restart the security layer mid-session.
func TestDualDoesNotSwitchVersions(t *testing.T) {
	vk, dk := mustKey(t), mustKey(t)
	vp, dp := newPipe()
	d := NewDual(DualConfig{
		Inner: dp,
		V2:    Config{SessionID: "sid-1", Static: dk, Authorised: [][]byte{vk.Public}},
	})
	v, _ := NewVault(Config{Inner: vp, SessionID: "sid-1", Static: vk, PeerStatic: dk.Public})
	_ = v.Start()
	if d.Version() != 2 {
		t.Fatalf("want v2, got %d", d.Version())
	}

	hello, _ := json.Marshal(map[string]string{"kx": "hello", "pub": "AAAA"})
	if err := vp.Send(hello); err != nil {
		t.Fatal(err)
	}
	if d.Version() != 2 {
		t.Fatal("a v1 hello must not downgrade an established v2 session")
	}
}

// The daemon never speaks first; before a peer opens there is nothing to send on.
func TestDualRefusesToSendBeforeAVersionExists(t *testing.T) {
	_, dp := newPipe()
	d := NewDual(DualConfig{Inner: dp, V2: Config{SessionID: "sid-1", Static: mustKey(t)}})
	if err := d.Send([]byte("x")); err == nil {
		t.Fatal("sending before a version is chosen must fail")
	}
}
