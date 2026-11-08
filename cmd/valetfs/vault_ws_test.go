package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anomalyco/valet-fs/internal/e2ee"
	"github.com/anomalyco/valet-fs/internal/hub"
	"github.com/anomalyco/valet-fs/internal/node"
	"github.com/anomalyco/valet-fs/internal/session"
	"github.com/anomalyco/valet-fs/internal/transport/ws"
	"github.com/anomalyco/valet-fs/internal/vault"
	"github.com/anomalyco/valet-fs/internal/vfs"
)

// v2Fixture is a real hub, a v2 daemon on it, and a vault directory whose
// identity that daemon accepts.
type v2Fixture struct {
	hubURL, sid, claim, vdir string
	daemonPub                []byte
}

func newV2Fixture(t *testing.T) *v2Fixture {
	t.Helper()
	srv := httptest.NewServer(hub.New())
	t.Cleanup(srv.Close)

	vdir := t.TempDir()
	vaultKey, _, err := session.LoadOrGenerateStatic(filepath.Join(vdir, vaultIdentityFile))
	if err != nil {
		t.Fatal(err)
	}
	memfs := vfs.New(0)
	n := node.New(node.Config{FS: memfs, Grace: time.Minute, Lock: func() { memfs.Wipe() },
		Mounted: func() bool { return true }})
	v1, err := e2ee.Generate()
	if err != nil {
		t.Fatal(err)
	}
	static, _, err := session.LoadOrGenerateStatic("")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := ws.NewClaimSecret()
	if err != nil {
		t.Fatal(err)
	}
	raw, sid, err := ws.DialDaemon(srv.URL, v1.PubB64(), session.PubB64(static.Public), claim)
	if err != nil {
		t.Fatal(err)
	}
	dc, err := session.NewDaemon(session.Config{
		Inner: raw, SessionID: sid, Static: static, Authorised: [][]byte{vaultKey.Public},
	})
	if err != nil {
		t.Fatal(err)
	}
	n.Attach(dc)
	_ = dc.Start(t.Context())
	t.Cleanup(func() { _ = dc.Close() })
	return &v2Fixture{hubURL: srv.URL, sid: sid, claim: claim, vdir: vdir, daemonPub: static.Public}
}

func (f *v2Fixture) target() vaultWSTarget {
	return vaultWSTarget{signaling: f.hubURL, sid: f.sid, claimSecret: f.claim, vdir: f.vdir}
}

func TestVaultWSFirstUseWithoutAnythingToCheckAgainstIsRefused(t *testing.T) {
	f := newV2Fixture(t)
	// The test process has no terminal, so there is nobody to ask.
	_, _, err := vaultWSDial(f.target())
	if err == nil || !strings.Contains(err.Error(), "--daemon-fingerprint") {
		t.Fatalf("expected a refusal that names --daemon-fingerprint, got %v", err)
	}
	if _, lerr := vault.LoadSession(f.vdir, f.sid); lerr == nil {
		t.Error("a refused first use must not be recorded")
	}
}

func TestVaultWSFingerprintFromTheDaemonConnectsAndIsRemembered(t *testing.T) {
	f := newV2Fixture(t)
	tg := f.target()
	tg.daemonFP = strings.ToLower(session.Fingerprint(f.daemonPub)) // case and dashes are not significant
	conn, cl, err := vaultWSDial(tg)
	if err != nil {
		t.Fatalf("dial with the right fingerprint: %v", err)
	}
	_ = cl
	_ = conn.Close()

	rec, err := vault.LoadSession(f.vdir, f.sid)
	if err != nil || rec.DaemonPubV2 != session.PubB64(f.daemonPub) {
		t.Fatalf("the daemon's key was not recorded: %+v %v", rec, err)
	}
	// Second run: nothing supplied, the recorded key is enough.
	conn, _, err = vaultWSDial(f.target())
	if err != nil {
		t.Fatalf("a remembered daemon should not need confirming again: %v", err)
	}
	_ = conn.Close()
}

func TestVaultWSWrongFingerprintOrKeyIsRefused(t *testing.T) {
	f := newV2Fixture(t)
	other, _, _ := session.LoadOrGenerateStatic("")

	tg := f.target()
	tg.daemonFP = session.Fingerprint(other.Public)
	if _, _, err := vaultWSDial(tg); err == nil || !strings.Contains(err.Error(), "does not match --daemon-fingerprint") {
		t.Fatalf("a fingerprint of another key must be refused, got %v", err)
	}

	tg = f.target()
	tg.daemonPub = session.PubB64(other.Public)
	if _, _, err := vaultWSDial(tg); err == nil || !strings.Contains(err.Error(), "does not match --daemon-pub") {
		t.Fatalf("a key that is not the hub's must be refused, got %v", err)
	}
}

func TestVaultWSDaemonKeyChangeAfterPairingIsRefused(t *testing.T) {
	f := newV2Fixture(t)
	other, _, _ := session.LoadOrGenerateStatic("")
	now := time.Now().UTC()
	if err := vault.SaveSession(f.vdir, vault.SessionRecord{
		SessionID: f.sid, SignalingURL: f.hubURL, PairedAt: now, LastSeen: now,
		DaemonPubV2: session.PubB64(other.Public), // what this vault saw before
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err := vaultWSDial(f.target())
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("expected an identity-changed refusal, got %v", err)
	}
}

func TestVaultWSUnauthorisedVaultSaysHowToFixIt(t *testing.T) {
	f := newV2Fixture(t)
	// A different vault directory, hence a different identity the daemon was
	// not told about.
	tg := f.target()
	tg.vdir = t.TempDir()
	tg.daemonFP = session.Fingerprint(f.daemonPub)
	_, _, err := vaultWSDial(tg)
	if err == nil || !strings.Contains(err.Error(), "vault identity") {
		t.Fatalf("expected a hint about `valetfs vault identity`, got %v", err)
	}
	if _, serr := os.Stat(filepath.Join(tg.vdir, vaultIdentityFile)); serr != nil {
		t.Errorf("the vault identity should have been created: %v", serr)
	}
}
