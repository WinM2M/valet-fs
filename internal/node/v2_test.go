package node_test

import (
	"context"
	"testing"
	"time"

	"github.com/anomalyco/valet-fs/internal/e2ee"
	"github.com/anomalyco/valet-fs/internal/node"
	"github.com/anomalyco/valet-fs/internal/rpc"
	"github.com/anomalyco/valet-fs/internal/session"
	"github.com/anomalyco/valet-fs/internal/transport/ws"
	"github.com/anomalyco/valet-fs/internal/vfs"
)

// startDualDaemon runs a daemon that serves both versions over the real hub,
// exactly as cmd/valetfs wires it.
func startDualDaemon(t *testing.T, hubURL string, authorised [][]byte) (sid, claim string, daemonPub []byte, fs *vfs.MemFS) {
	t.Helper()

	memfs := vfs.New(0)
	n := node.New(node.Config{FS: memfs, Grace: time.Minute, Lock: func() { memfs.Wipe() },
		Mounted: func() bool { return true }})

	v1kp, err := e2ee.Generate()
	if err != nil {
		t.Fatal(err)
	}
	static, _, err := session.LoadOrGenerateStatic("")
	if err != nil {
		t.Fatal(err)
	}
	claim, err = ws.NewClaimSecret()
	if err != nil {
		t.Fatal(err)
	}
	raw, sid, err := ws.DialDaemon(hubURL, v1kp.PubB64(), session.PubB64(static.Public), claim)
	if err != nil {
		t.Fatalf("daemon dial: %v", err)
	}
	dc := session.NewDual(session.DualConfig{
		Inner:    raw,
		V1Static: v1kp,
		V2:       session.Config{SessionID: sid, Static: static, Authorised: authorised},
	})
	n.Attach(dc)
	dc.Start()
	t.Cleanup(func() { _ = dc.Close() })
	return sid, claim, static.Public, memfs
}

// An authorised vault gets a v2 session over the real hub and can work.
func TestV2SessionOverTheHub(t *testing.T) {
	hubURL := newHub(t)

	vaultKey, _, err := session.LoadOrGenerateStatic("")
	if err != nil {
		t.Fatal(err)
	}
	sid, claim, daemonPub, memfs := startDualDaemon(t, hubURL, [][]byte{vaultKey.Public})

	raw, _, _, err := ws.DialController(hubURL, sid, claim)
	if err != nil {
		t.Fatalf("vault dial: %v", err)
	}
	defer raw.Close()

	v, err := session.NewVault(session.Config{
		Inner: raw, SessionID: sid, Static: vaultKey, PeerStatic: daemonPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	cl := rpc.NewClient(v)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Start waits for the handshake, so the first call below cannot race it.
	if err := v.Start(ctx); err != nil {
		t.Fatalf("v2 handshake over the hub: %v", err)
	}
	if _, err := cl.Call(ctx, rpc.MethodWrite, map[string]any{
		"path": "/keys/token", "content": "s3cret",
	}); err != nil {
		t.Fatalf("write over v2: %v", err)
	}
	if got, err := memfs.Read("/keys/token"); err != nil || string(got) != "s3cret" {
		t.Fatalf("the daemon did not receive the write: %q %v", got, err)
	}
}

// A vault the daemon has not been told to accept completes a handshake and is
// still refused: authentication is not authorisation.
func TestV2UnauthorisedVaultCannotWork(t *testing.T) {
	hubURL := newHub(t)

	authorised, _, err := session.LoadOrGenerateStatic("")
	if err != nil {
		t.Fatal(err)
	}
	attacker, _, err := session.LoadOrGenerateStatic("")
	if err != nil {
		t.Fatal(err)
	}
	sid, claim, daemonPub, memfs := startDualDaemon(t, hubURL, [][]byte{authorised.Public})

	raw, _, _, err := ws.DialController(hubURL, sid, claim)
	if err != nil {
		t.Fatalf("vault dial: %v", err)
	}
	defer raw.Close()

	v, err := session.NewVault(session.Config{
		Inner: raw, SessionID: sid, Static: attacker, PeerStatic: daemonPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	cl := rpc.NewClient(v)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Expected to fail. The daemon closes ITS socket on refusal, but the hub
	// does not close the vault's, so from here the refusal looks like silence
	// and the context is what ends the wait. Worth knowing: a refused vault
	// sees a timeout, not an error message, and the daemon log is where the
	// reason is.
	if err := v.Start(ctx); err == nil {
		t.Fatal("an unauthorised vault must not complete a session")
	}
	if _, err := cl.Call(ctx, rpc.MethodWrite, map[string]any{
		"path": "/keys/token", "content": "stolen",
	}); err == nil {
		t.Fatal("an unauthorised vault must not be able to write")
	}
	if memfs.Used() != 0 {
		t.Fatal("nothing from an unauthorised vault may reach the file system")
	}
}
