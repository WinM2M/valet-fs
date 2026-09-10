package session

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Produces the wire transcript the app's independent implementation is checked
// against, at ../../testdata/session/v2_transcript.json.
//
// The official Noise vectors prove each side implements the handshake. They say
// nothing about the layer around it — the frame shapes, the prologue, what goes
// into the additional data. Two implementations can each be perfectly
// Noise-conformant and still fail to talk, and that failure would only show up
// against a real daemon.
//
// So this records a real session produced by the code that actually runs, with
// the ephemeral keys fixed so it can be replayed exactly.
//
//	VALETFS_WRITE_TRANSCRIPT=1 go test ./internal/session -run TestWriteTranscript
func TestWriteTranscript(t *testing.T) {
	if os.Getenv("VALETFS_WRITE_TRANSCRIPT") == "" {
		t.Skip("set VALETFS_WRITE_TRANSCRIPT=1 to regenerate")
	}

	const sid = "0123456789abcdef0123456789abcdef"
	vaultPriv := bytes.Repeat([]byte{0x11}, 32)
	daemonPriv := bytes.Repeat([]byte{0x22}, 32)
	vaultEph := bytes.Repeat([]byte{0x33}, 32)
	daemonEph := bytes.Repeat([]byte{0x44}, 32)

	vaultKey, err := keyFromPrivate(vaultPriv)
	if err != nil {
		t.Fatal(err)
	}
	daemonKey, err := keyFromPrivate(daemonPriv)
	if err != nil {
		t.Fatal(err)
	}

	vp, dp := newPipe()
	v, err := NewVault(Config{
		Inner: vp, SessionID: sid, Static: vaultKey,
		PeerStatic: daemonKey.Public, Random: bytes.NewReader(vaultEph),
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDaemon(Config{
		Inner: dp, SessionID: sid, Static: daemonKey,
		Authorised: [][]byte{vaultKey.Public}, Random: bytes.NewReader(daemonEph),
	})
	if err != nil {
		t.Fatal(err)
	}

	var toDaemon, toVault [][]byte
	d.OnData(func(b []byte) { toDaemon = append(toDaemon, append([]byte(nil), b...)) })
	v.OnData(func(b []byte) { toVault = append(toVault, append([]byte(nil), b...)) })

	ctx, cancel := shortCtx()
	defer cancel()
	if err := v.Start(ctx); err != nil {
		t.Fatal(err)
	}

	vaultSays := [][]byte{
		[]byte(`{"v":1,"type":"REQ","method":"STATUS"}`),
		[]byte(`{"v":1,"type":"REQ","method":"WRITE","params":{"path":"/keys/token"}}`),
	}
	daemonSays := [][]byte{
		[]byte(`{"v":1,"type":"RES","ok":true}`),
	}
	for _, m := range vaultSays {
		if err := v.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range daemonSays {
		if err := d.Send(m); err != nil {
			t.Fatal(err)
		}
	}

	doc := map[string]any{
		"note": "A real v2 session recorded from internal/session, with fixed ephemerals so " +
			"it replays exactly. The official Noise vectors prove the handshake; this proves " +
			"the layer around it — frame shapes, prologue, and additional data — which is where " +
			"two conformant implementations can still fail to talk.",
		"protocol":          Protocol,
		"session_id":        sid,
		"vault_priv":        hex.EncodeToString(vaultPriv),
		"vault_pub":         hex.EncodeToString(vaultKey.Public),
		"daemon_priv":       hex.EncodeToString(daemonPriv),
		"daemon_pub":        hex.EncodeToString(daemonKey.Public),
		"vault_eph":         hex.EncodeToString(vaultEph),
		"daemon_eph":        hex.EncodeToString(daemonEph),
		"frames_vault":      framesOf(vp),
		"frames_daemon":     framesOf(dp),
		"vault_plaintexts":  b64all(vaultSays),
		"daemon_plaintexts": b64all(daemonSays),
	}
	body, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("../../testdata/session", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../../testdata/session/v2_transcript.json", body, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d vault frames and %d daemon frames", len(framesOf(vp)), len(framesOf(dp)))
}

func framesOf(p *pipe) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.sent))
	for _, f := range p.sent {
		out = append(out, string(f))
	}
	return out
}

func b64all(ms [][]byte) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, base64.StdEncoding.EncodeToString(m))
	}
	return out
}
