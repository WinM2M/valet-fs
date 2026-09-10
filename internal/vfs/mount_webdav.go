package vfs

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/webdav"
)

// WebdavMounter exposes a MemFS over a loopback HTTP server speaking the
// WebDAV protocol. It is the universal fallback used whenever a real
// kernel-backed mount (FUSE on Linux, native WebDAV redirector on Windows)
// is unavailable, e.g. inside a container without /dev/fuse.
//
// Agents and users access files via plain HTTP at the printed URL; no kernel
// driver, no elevated privileges, and no sudo are required.
type WebdavMounter struct {
	mu     sync.Mutex
	fs     *MemFS
	srv    *http.Server
	addr   string
	token  string
	remote bool
	doneCh chan error
}

// NewWebdavMounter creates a WebDAV mounter listening on 127.0.0.1:<port>.
// If addr is empty an ephemeral free port is selected automatically.
//
// token authenticates every request. Loopback is NOT an authorization
// boundary: any other process (or user) on the same host can reach the port,
// so an unauthenticated server hands the whole vault to anything that can run
// curl. An empty token is rejected at Mount time rather than silently serving
// in the clear.
//
// allowRemote must be set explicitly to bind anywhere other than loopback.
func NewWebdavMounter(m *MemFS, addr, token string, allowRemote bool) *WebdavMounter {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	return &WebdavMounter{fs: m, addr: addr, token: token, remote: allowRemote, doneCh: make(chan error, 1)}
}

// isLoopbackAddr reports whether addr binds only to a loopback interface.
// An empty or wildcard host ("", "0.0.0.0", "[::]") reaches the network.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// authorize checks the request credential in constant time. Three carriers are
// accepted because WebDAV clients differ: HTTP Basic (Finder, davfs2 and other
// kernel clients cannot set custom headers; any username, password = token),
// Authorization: Bearer, and a ?token= query parameter for quick curl use.
func (w *WebdavMounter) authorize(r *http.Request) bool {
	if w.token == "" {
		return false
	}
	if _, pass, ok := r.BasicAuth(); ok && tokenEqual(pass, w.token) {
		return true
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if tokenEqual(strings.TrimPrefix(h, "Bearer "), w.token) {
			return true
		}
	}
	return tokenEqual(r.URL.Query().Get("token"), w.token)
}

func tokenEqual(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// authHandler rejects unauthenticated requests before the WebDAV handler ever
// sees a path.
func (w *WebdavMounter) authHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !w.authorize(r) {
			rw.Header().Set("WWW-Authenticate", `Basic realm="valetfs"`)
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// Addr returns the bound TCP address once Mount has started listening.
func (w *WebdavMounter) Addr() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.srv == nil {
		return w.addr
	}
	return w.srv.Addr
}

// Mount blocks while the WebDAV server is running. The mountpoint argument is
// accepted for parity with the Mounter interface but is informational only;
// the server is always exposed via HTTP loopback.
func (w *WebdavMounter) Mount(_ string) error {
	if w.token == "" {
		return errors.New("webdav: refusing to serve without an auth token")
	}
	if !w.remote && !isLoopbackAddr(w.addr) {
		return fmt.Errorf("webdav: refusing to bind %s without --webdav-allow-remote "+
			"(the server would expose every secret to the network)", w.addr)
	}

	handler := &webdav.Handler{
		FileSystem: newWebdavAdapter(w.fs),
		LockSystem: webdav.NewMemLS(),
	}

	// Bind first so we can resolve the actual port before logging.
	ln, err := net.Listen("tcp", w.addr)
	if err != nil {
		return fmt.Errorf("webdav listen: %w", err)
	}

	w.mu.Lock()
	w.srv = &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           w.authHandler(handler),
		ReadHeaderTimeout: 5 * time.Second,
	}
	w.mu.Unlock()

	err = w.srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Unmount gracefully stops the WebDAV server.
func (w *WebdavMounter) Unmount() error {
	w.mu.Lock()
	srv := w.srv
	w.mu.Unlock()
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

func (*WebdavMounter) Backend() string { return "webdav" }
