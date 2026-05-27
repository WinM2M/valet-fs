// Package daemon wires together the VFS, sync, and signaling layers and
// exposes the local HTTP control API used in --dev mode.
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	stdpath "path"
	"sync"
	"time"

	"github.com/anomalyco/valet-fs/internal/config"
	syncpkg "github.com/anomalyco/valet-fs/internal/sync"
	"github.com/anomalyco/valet-fs/internal/vfs"
)

func parentDir(p string) string { return stdpath.Dir(p) }

// Daemon owns the long-lived resources of the valetd process.
type Daemon struct {
	cfg     *config.Config
	fs      *vfs.MemFS
	mounter vfs.Mounter
	repo    *syncpkg.Repo

	mu       sync.Mutex
	mounted  bool
	devSrv   *http.Server
	mountErr chan error
}

// New constructs a Daemon ready to run.
func New(cfg *config.Config) (*Daemon, error) {
	memfs := vfs.New(cfg.QuotaBytes)
	repo, err := syncpkg.Open(cfg.GitTempDir)
	if err != nil {
		return nil, fmt.Errorf("open sync repo: %w", err)
	}
	return &Daemon{
		cfg:      cfg,
		fs:       memfs,
		mounter:  vfs.NewMounter(memfs),
		repo:     repo,
		mountErr: make(chan error, 1),
	}, nil
}

// MemFS exposes the in-memory file system. Used by the WebRTC layer to ship
// the canonical view of the cluster to paired mobile apps.
func (d *Daemon) MemFS() *vfs.MemFS { return d.fs }

// Mount idempotently brings the VFS online.
func (d *Daemon) Mount() error {
	d.mu.Lock()
	if d.mounted {
		d.mu.Unlock()
		return nil
	}
	d.mounted = true
	d.mu.Unlock()

	go func() {
		log.Printf("valetfs: mounting at %s", d.cfg.MountPoint)
		d.mountErr <- d.mounter.Mount(d.cfg.MountPoint)
	}()
	return nil
}

// Unmount tears the VFS down, leaving the heap intact (use Shutdown for wipe).
func (d *Daemon) Unmount() error {
	d.mu.Lock()
	if !d.mounted {
		d.mu.Unlock()
		return nil
	}
	d.mounted = false
	d.mu.Unlock()
	log.Printf("valetfs: unmounting %s", d.cfg.MountPoint)
	return d.mounter.Unmount()
}

// Sync commits a manifest of the current VFS state to the diff repo.
func (d *Daemon) Sync() (string, error) {
	snap := d.fs.Snapshot()
	msg := fmt.Sprintf("sync %s", time.Now().UTC().Format(time.RFC3339))
	return d.repo.Commit(snap, msg)
}

// Shutdown performs Graceful Shutdown semantics: unmount + memory wipe + repo wipe.
// This is the function to call from SIGINT/SIGTERM handlers.
func (d *Daemon) Shutdown(ctx context.Context) error {
	if d.devSrv != nil {
		_ = d.devSrv.Shutdown(ctx)
	}
	if err := d.Unmount(); err != nil {
		log.Printf("valetfs: unmount error during shutdown: %v", err)
	}
	d.fs.Wipe()
	if err := d.repo.Wipe(); err != nil {
		log.Printf("valetfs: repo wipe error: %v", err)
	}
	return nil
}

// StartDevAPI launches the localhost HTTP control server used during Phase 1.
func (d *Daemon) StartDevAPI() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mount", d.handleMount)
	mux.HandleFunc("/unmount", d.handleUnmount)
	mux.HandleFunc("/sync", d.handleSync)
	mux.HandleFunc("/status", d.handleStatus)
	mux.HandleFunc("/files", d.handleFiles)

	d.devSrv = &http.Server{
		Addr:              d.cfg.DevAPIAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("valetfs: dev control API on http://%s", d.cfg.DevAPIAddr)
		if err := d.devSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("valetfs: dev API server error: %v", err)
		}
	}()
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (d *Daemon) handleMount(w http.ResponseWriter, _ *http.Request) {
	if err := d.Mount(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mounted": true, "mountpoint": d.cfg.MountPoint})
}

func (d *Daemon) handleUnmount(w http.ResponseWriter, _ *http.Request) {
	if err := d.Unmount(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mounted": false})
}

func (d *Daemon) handleSync(w http.ResponseWriter, _ *http.Request) {
	hash, err := d.Sync()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"commit": hash})
}

func (d *Daemon) handleStatus(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	mounted := d.mounted
	d.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"mounted":    mounted,
		"mountpoint": d.cfg.MountPoint,
		"used":       d.fs.Used(),
		"quota":      d.cfg.QuotaBytes,
	})
}

// handleFiles exposes a small POST/GET/DELETE surface for dev testing without
// having to actually traverse the FUSE mount.
func (d *Daemon) handleFiles(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing path"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		data, err := d.fs.Read(path)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
	case http.MethodPost, http.MethodPut:
		var body struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// Convenience for dev mode: auto-create parent directories.
		if dir := parentDir(path); dir != "" && dir != "/" {
			_ = d.fs.MkdirAll(dir, 0o755)
		}
		if err := d.fs.Write(path, []byte(body.Content), 0o600); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case http.MethodDelete:
		if err := d.fs.Remove(path); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
