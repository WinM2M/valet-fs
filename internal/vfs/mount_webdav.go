package vfs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	doneCh chan error
}

// NewWebdavMounter creates a WebDAV mounter listening on 127.0.0.1:<port>.
// If addr is empty an ephemeral free port is selected automatically.
func NewWebdavMounter(m *MemFS, addr string) *WebdavMounter {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	return &WebdavMounter{fs: m, addr: addr, doneCh: make(chan error, 1)}
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
		Handler:           handler,
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
