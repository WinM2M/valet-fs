package node_test

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/anomalyco/valet-fs/internal/e2ee"
	"github.com/anomalyco/valet-fs/internal/hub"
	"github.com/anomalyco/valet-fs/internal/node"
	"github.com/anomalyco/valet-fs/internal/rpc"
	"github.com/anomalyco/valet-fs/internal/transport/ws"
	"github.com/anomalyco/valet-fs/internal/vfs"
)

// daemonHarness models the daemon side: a MemFS, a logical mount flag, and the
// authoritative grace-driven lock (unmount + wipe).
type daemonHarness struct {
	fs  *vfs.MemFS
	sid string

	mu      sync.Mutex
	mounted bool
}

func (h *daemonHarness) isMounted() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mounted
}

func startDaemon(t *testing.T, hubURL string, grace time.Duration) *daemonHarness {
	t.Helper()
	h := &daemonHarness{fs: vfs.New(0), mounted: true}
	lock := func() {
		h.mu.Lock()
		h.mounted = false
		h.mu.Unlock()
		h.fs.Wipe()
	}
	n := node.New(node.Config{FS: h.fs, Grace: grace, Lock: lock, Mounted: h.isMounted})
	conn, sid, err := ws.DialDaemon(hubURL, "")
	if err != nil {
		t.Fatalf("daemon dial: %v", err)
	}
	n.Attach(conn)
	conn.Start()
	h.sid = sid
	t.Cleanup(func() { _ = conn.Close() })
	return h
}

func connectVault(t *testing.T, hubURL, sid string) (*ws.Conn, *rpc.Client) {
	t.Helper()
	conn, _, err := ws.DialController(hubURL, sid)
	if err != nil {
		t.Fatalf("vault dial: %v", err)
	}
	cl := rpc.NewClient(conn)
	conn.Start()
	return conn, cl
}

func callCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}

// pushFile sends a WRITE for one file (base64 content).
func pushFile(t *testing.T, cl *rpc.Client, p string, content []byte) {
	t.Helper()
	ctx, cancel := callCtx()
	defer cancel()
	_, err := cl.Call(ctx, rpc.MethodWrite, map[string]any{
		"path":        p,
		"content_b64": base64.StdEncoding.EncodeToString(content),
	})
	if err != nil {
		t.Fatalf("WRITE %s: %v", p, err)
	}
}

func newHub(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(hub.New())
	t.Cleanup(srv.Close)
	return srv.URL
}

// T1: pairing + push — vault entries land in the daemon MemFS.
func TestPairAndPush(t *testing.T) {
	hubURL := newHub(t)
	d := startDaemon(t, hubURL, 5*time.Second)
	conn, cl := connectVault(t, hubURL, d.sid)
	defer conn.Close()

	pushFile(t, cl, "/keys/secret.txt", []byte("token=abc123"))

	got, err := d.fs.Read("/keys/secret.txt")
	if err != nil {
		t.Fatalf("daemon read: %v", err)
	}
	if string(got) != "token=abc123" {
		t.Fatalf("content mismatch: %q", got)
	}
}

// S1/T2: reliable rejoin — repeated connect+STATUS on the same session all
// succeed. This is the behaviour the WebRTC path could not guarantee.
func TestReliableRejoin(t *testing.T) {
	hubURL := newHub(t)
	d := startDaemon(t, hubURL, 5*time.Second)

	// Seed one file.
	conn, cl := connectVault(t, hubURL, d.sid)
	pushFile(t, cl, "/keys/secret.txt", []byte("v"))
	conn.Close()

	for i := 0; i < 10; i++ {
		conn, cl := connectVault(t, hubURL, d.sid)
		ctx, cancel := callCtx()
		res, err := cl.Call(ctx, rpc.MethodStatus, nil)
		cancel()
		if err != nil {
			t.Fatalf("rejoin %d STATUS failed: %v", i, err)
		}
		if mounted, _ := res.Result["mounted"].(bool); !mounted {
			t.Fatalf("rejoin %d: expected mounted", i)
		}
		conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
}

// S3: grace expiry auto-locks (unmount + wipe).
func TestGraceAutoLock(t *testing.T) {
	hubURL := newHub(t)
	d := startDaemon(t, hubURL, 200*time.Millisecond)

	conn, cl := connectVault(t, hubURL, d.sid)
	pushFile(t, cl, "/keys/secret.txt", []byte("token"))
	if !d.isMounted() {
		t.Fatal("expected mounted after pair")
	}
	conn.Close() // vault "app closed"

	time.Sleep(600 * time.Millisecond) // exceed grace

	if d.isMounted() {
		t.Fatal("expected auto-lock after grace expiry")
	}
	if d.fs.Used() != 0 {
		t.Fatalf("expected wiped FS, used=%d", d.fs.Used())
	}
}

// S4: reconnect within grace cancels the auto-lock.
func TestGraceCancelOnReconnect(t *testing.T) {
	hubURL := newHub(t)
	d := startDaemon(t, hubURL, 1*time.Second)

	conn, cl := connectVault(t, hubURL, d.sid)
	pushFile(t, cl, "/keys/secret.txt", []byte("token"))
	conn.Close()

	time.Sleep(200 * time.Millisecond) // within grace
	conn2, _ := connectVault(t, hubURL, d.sid)
	defer conn2.Close()

	time.Sleep(1200 * time.Millisecond) // past original deadline

	if !d.isMounted() {
		t.Fatal("expected still mounted (grace cancelled by reconnect)")
	}
	if d.fs.Used() == 0 {
		t.Fatal("expected file retained after reconnect")
	}
}

// S5: files added on the daemon while the vault is offline reconcile back to the
// vault (source of truth) on reconnect via MANIFEST + PULL.
func TestReconcileDaemonSideAdditions(t *testing.T) {
	hubURL := newHub(t)
	d := startDaemon(t, hubURL, 5*time.Second)

	// Vault holds file A and pushes it.
	vaultFS := vfs.New(0)
	_ = vaultFS.MkdirAll("/keys", 0o755)
	_ = vaultFS.Write("/keys/a.txt", []byte("A"), 0o600)
	conn, cl := connectVault(t, hubURL, d.sid)
	pushFile(t, cl, "/keys/a.txt", []byte("A"))
	conn.Close() // vault offline

	// Desktop-local addition on the daemon while vault is away.
	_ = d.fs.MkdirAll("/keys", 0o755)
	if err := d.fs.Write("/keys/b.txt", []byte("B"), 0o600); err != nil {
		t.Fatalf("daemon local write: %v", err)
	}

	// Vault reconnects and reconciles.
	conn2, cl2 := connectVault(t, hubURL, d.sid)
	defer conn2.Close()

	ctx, cancel := callCtx()
	res, err := cl2.Call(ctx, rpc.MethodManifest, map[string]any{"since": 0})
	cancel()
	if err != nil {
		t.Fatalf("MANIFEST: %v", err)
	}
	entries, _ := res.Result["entries"].([]any)

	// Diff against local vault shas; PULL anything missing/different.
	have := manifestSHAs(vaultFS)
	var missing []any
	for _, e := range entries {
		m, _ := e.(map[string]any)
		p, _ := m["path"].(string)
		sha, _ := m["sha"].(string)
		if have[p] != sha {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		t.Fatal("expected /keys/b.txt to be detected as missing")
	}

	ctx2, cancel2 := callCtx()
	pres, err := cl2.Call(ctx2, rpc.MethodPull, map[string]any{"paths": missing})
	cancel2()
	if err != nil {
		t.Fatalf("PULL: %v", err)
	}
	blobs, _ := pres.Result["blobs"].(map[string]any)
	for p, v := range blobs {
		b64, _ := v.(string)
		data, derr := base64.StdEncoding.DecodeString(b64)
		if derr != nil {
			t.Fatalf("decode blob %s: %v", p, derr)
		}
		_ = vaultFS.MkdirAll("/keys", 0o755)
		if err := vaultFS.Write(p, data, 0o600); err != nil {
			t.Fatalf("vault merge %s: %v", p, err)
		}
	}

	// Vault (source of truth) now has both A and B.
	if got, _ := vaultFS.Read("/keys/a.txt"); string(got) != "A" {
		t.Fatalf("vault lost A: %q", got)
	}
	if got, err := vaultFS.Read("/keys/b.txt"); err != nil || string(got) != "B" {
		t.Fatalf("vault did not reconcile B: %q err=%v", got, err)
	}
}

// S6: explicit UNMOUNT from the vault locks the daemon immediately.
func TestExplicitUnmount(t *testing.T) {
	hubURL := newHub(t)
	d := startDaemon(t, hubURL, 5*time.Second)

	conn, cl := connectVault(t, hubURL, d.sid)
	defer conn.Close()
	pushFile(t, cl, "/keys/secret.txt", []byte("token"))
	if !d.isMounted() {
		t.Fatal("expected mounted")
	}

	ctx, cancel := callCtx()
	_, err := cl.Call(ctx, rpc.MethodUnmount, nil)
	cancel()
	if err != nil {
		t.Fatalf("UNMOUNT: %v", err)
	}
	if d.isMounted() {
		t.Fatal("expected unmounted after UNMOUNT")
	}
	if d.fs.Used() != 0 {
		t.Fatalf("expected wiped FS, used=%d", d.fs.Used())
	}
}

// E2EE: full encrypted round trip over the hub (the hub sees only ciphertext).
func TestE2EEEncryptedRoundTrip(t *testing.T) {
	hubURL := newHub(t)

	// Daemon side with E2EE.
	dkp, err := e2ee.Generate()
	if err != nil {
		t.Fatal(err)
	}
	h := &daemonHarness{fs: vfs.New(0), mounted: true}
	lock := func() {
		h.mu.Lock()
		h.mounted = false
		h.mu.Unlock()
		h.fs.Wipe()
	}
	n := node.New(node.Config{FS: h.fs, Grace: 5 * time.Second, Lock: lock, Mounted: h.isMounted})
	rawD, sid, err := ws.DialDaemon(hubURL, dkp.PubB64())
	if err != nil {
		t.Fatalf("daemon dial: %v", err)
	}
	dConn := e2ee.WrapDaemon(rawD, dkp)
	n.Attach(dConn)
	dConn.Start()
	t.Cleanup(func() { _ = dConn.Close() })

	// Vault side with E2EE (daemon pub authenticated via claim/QR).
	rawV, daemonPub, err := ws.DialController(hubURL, sid)
	if err != nil {
		t.Fatalf("vault dial: %v", err)
	}
	if daemonPub != dkp.PubB64() {
		t.Fatalf("daemon pub mismatch: got %q", daemonPub)
	}
	vkp, _ := e2ee.Generate()
	vConn, err := e2ee.WrapController(rawV, vkp, daemonPub)
	if err != nil {
		t.Fatalf("wrap controller: %v", err)
	}
	cl := rpc.NewClient(vConn)
	vConn.Start()
	defer vConn.Close()

	// Encrypted WRITE, then verify the daemon decrypted it correctly.
	ctx, cancel := callCtx()
	_, err = cl.Call(ctx, rpc.MethodWrite, map[string]any{
		"path":        "/keys/x",
		"content_b64": base64.StdEncoding.EncodeToString([]byte("secret")),
	})
	cancel()
	if err != nil {
		t.Fatalf("encrypted WRITE: %v", err)
	}
	got, err := h.fs.Read("/keys/x")
	if err != nil || string(got) != "secret" {
		t.Fatalf("daemon decrypt mismatch: %q err=%v", got, err)
	}

	// Encrypted STATUS round trip.
	ctx2, cancel2 := callCtx()
	res, err := cl.Call(ctx2, rpc.MethodStatus, nil)
	cancel2()
	if err != nil {
		t.Fatalf("encrypted STATUS: %v", err)
	}
	if mounted, _ := res.Result["mounted"].(bool); !mounted {
		t.Fatal("expected mounted via encrypted status")
	}
}

func manifestSHAs(fs *vfs.MemFS) map[string]string {
	out := map[string]string{}
	for _, e := range fs.Manifest() {
		out[e.Path] = e.SHA
	}
	return out
}
