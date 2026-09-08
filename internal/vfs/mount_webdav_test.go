package vfs

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// startTestWebdav brings up a mounter on an ephemeral loopback port and returns
// its base URL. Loopback is not an authorization boundary, so every one of
// these requests stands in for "another process on the same host".
func startTestWebdav(t *testing.T, token string) (*WebdavMounter, string) {
	t.Helper()
	fs := New(1 << 20)
	if err := fs.MkdirAll("/keys", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := fs.Write("/keys/aws.env", []byte("SECRET=1"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	w := NewWebdavMounter(fs, "127.0.0.1:0", token, false)
	go func() { _ = w.Mount("") }()
	t.Cleanup(func() { _ = w.Unmount() })

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if addr := w.Addr(); addr != "" && !strings.HasSuffix(addr, ":0") {
			return w, "http://" + addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("webdav did not bind in time")
	return nil, ""
}

func do(t *testing.T, req *http.Request) int {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestWebdavRejectsUnauthenticated(t *testing.T) {
	_, base := startTestWebdav(t, "s3cret")

	req, _ := http.NewRequest("GET", base+"/keys/aws.env", nil)
	if got := do(t, req); got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET: want 401, got %d", got)
	}

	req, _ = http.NewRequest("PROPFIND", base+"/", nil)
	req.Header.Set("Depth", "1")
	if got := do(t, req); got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated PROPFIND: want 401, got %d", got)
	}

	req, _ = http.NewRequest("GET", base+"/keys/aws.env?token=wrong", nil)
	if got := do(t, req); got != http.StatusUnauthorized {
		t.Fatalf("wrong token: want 401, got %d", got)
	}
}

func TestWebdavAcceptsEveryCredentialCarrier(t *testing.T) {
	_, base := startTestWebdav(t, "s3cret")

	// HTTP Basic: the only carrier kernel WebDAV clients (Finder, davfs2) have.
	req, _ := http.NewRequest("GET", base+"/keys/aws.env", nil)
	req.SetBasicAuth("valetfs", "s3cret")
	if got := do(t, req); got != http.StatusOK {
		t.Fatalf("basic auth: want 200, got %d", got)
	}

	req, _ = http.NewRequest("GET", base+"/keys/aws.env", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	if got := do(t, req); got != http.StatusOK {
		t.Fatalf("bearer: want 200, got %d", got)
	}

	req, _ = http.NewRequest("GET", base+"/keys/aws.env?token=s3cret", nil)
	if got := do(t, req); got != http.StatusOK {
		t.Fatalf("query token: want 200, got %d", got)
	}
}

func TestWebdavRefusesToServeWithoutToken(t *testing.T) {
	w := NewWebdavMounter(New(1<<20), "127.0.0.1:0", "", false)
	if err := w.Mount(""); err == nil {
		t.Fatal("want an error when no token is configured, got nil")
	}
}

func TestWebdavRefusesRemoteBindWithoutOptIn(t *testing.T) {
	w := NewWebdavMounter(New(1<<20), "0.0.0.0:0", "s3cret", false)
	if err := w.Mount(""); err == nil {
		t.Fatal("want an error binding 0.0.0.0 without --webdav-allow-remote, got nil")
	}
	if !isLoopbackAddr("127.0.0.1:0") || !isLoopbackAddr("[::1]:80") || !isLoopbackAddr("localhost:1") {
		t.Fatal("loopback addresses misclassified")
	}
	if isLoopbackAddr("0.0.0.0:0") || isLoopbackAddr("[::]:0") || isLoopbackAddr("10.0.0.1:1") {
		t.Fatal("non-loopback addresses misclassified as loopback")
	}
}
