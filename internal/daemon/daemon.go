// Package daemon wires together the VFS, sync, and signaling layers and
// exposes the local HTTP control API used in --dev mode.
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	stdpath "path"
	"path/filepath"
	"strings"
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
	webdav  *vfs.WebdavMounter
	repo    *syncpkg.Repo

	mu       sync.Mutex
	mounted  bool
	fuseErr  string
	webdavOn bool
	devSrv   *http.Server
	devAddr  string
}

type RuntimeState struct {
	ControlURL   string `json:"control_url"`
	ControlAddr  string `json:"control_addr"`
	ControlToken string `json:"control_token"`
	WebDAVAddr   string `json:"webdav_addr"`
	Mountpoint   string `json:"mountpoint"`
}

// New constructs a Daemon ready to run.
func New(cfg *config.Config) (*Daemon, error) {
	memfs := vfs.New(cfg.QuotaBytes)
	repo, err := syncpkg.Open(cfg.GitTempDir)
	if err != nil {
		return nil, fmt.Errorf("open sync repo: %w", err)
	}
	return &Daemon{
		cfg:     cfg,
		fs:      memfs,
		mounter: vfs.NewMounter(memfs),
		webdav:  vfs.NewWebdavMounter(memfs, cfg.WebdavAddr),
		repo:    repo,
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

	if !d.cfg.WebdavDisabled {
		go func() {
			if err := d.webdav.Mount(d.cfg.MountPoint); err != nil {
				d.mu.Lock()
				d.webdavOn = false
				d.mu.Unlock()
				log.Printf("valetfs: webdav error: %v", err)
			}
		}()
		go d.waitWebDAVReady()
	}

	go func() {
		log.Printf("valetfs: mounting at %s", d.cfg.MountPoint)
		if err := d.mounter.Mount(d.cfg.MountPoint); err != nil {
			d.mu.Lock()
			d.fuseErr = err.Error()
			d.mu.Unlock()
			log.Printf("valetfs: fuse mount unavailable: %v", err)
		}
	}()
	return nil
}

func (d *Daemon) waitWebDAVReady() {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		addr := d.webdav.Addr()
		if addr != "" && !strings.HasSuffix(addr, ":0") {
			d.mu.Lock()
			d.webdavOn = true
			d.mu.Unlock()
			_ = d.writeRuntimeState()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
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
	if err := d.mounter.Unmount(); err != nil {
		return err
	}
	if !d.cfg.WebdavDisabled {
		if err := d.webdav.Unmount(); err != nil {
			return err
		}
	}
	return nil
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
	mux.HandleFunc("/mkdir", d.handleMkdir)
	mux.HandleFunc("/rmdir", d.handleRmdir)
	mux.HandleFunc("/shutdown", d.handleShutdown)

	d.devSrv = &http.Server{
		Addr:              d.cfg.DevAPIAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", d.cfg.DevAPIAddr)
	if err != nil {
		return err
	}
	d.devAddr = ln.Addr().String()
	go func() {
		log.Printf("valetfs: control API on http://%s?token=%s", d.devAddr, d.cfg.ControlToken)
		if err := d.devSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("valetfs: dev API server error: %v", err)
		}
	}()
	if d.cfg.RecordRuntimeState {
		if err := d.writeRuntimeState(); err != nil {
			log.Printf("valetfs: runtime state write error: %v", err)
		}
	}
	return nil
}

func (d *Daemon) auth(r *http.Request) bool {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		tok = r.Header.Get("X-Valet-Token")
	}
	return tok != "" && tok == d.cfg.ControlToken
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (d *Daemon) handleMount(w http.ResponseWriter, r *http.Request) {
	if !d.auth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if err := d.Mount(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mounted": true, "mountpoint": d.cfg.MountPoint})
}

func (d *Daemon) handleUnmount(w http.ResponseWriter, r *http.Request) {
	if !d.auth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if err := d.Unmount(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mounted": false})
}

func (d *Daemon) handleSync(w http.ResponseWriter, r *http.Request) {
	if !d.auth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	hash, err := d.Sync()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"commit": hash})
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !d.auth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	d.mu.Lock()
	mounted := d.mounted
	fuseErr := d.fuseErr
	webdavOn := d.webdavOn
	d.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"mounted":    mounted,
		"mountpoint": d.cfg.MountPoint,
		"fuse": map[string]any{
			"mounted": mounted,
			"error":   fuseErr,
		},
		"webdav": map[string]any{
			"enabled": !d.cfg.WebdavDisabled,
			"serving": webdavOn,
			"addr":    d.webdav.Addr(),
		},
		"used":  d.fs.Used(),
		"quota": d.cfg.QuotaBytes,
	})
}

// handleFiles exposes a small POST/GET/DELETE surface for dev testing without
// having to actually traverse the FUSE mount.
func (d *Daemon) handleFiles(w http.ResponseWriter, r *http.Request) {
	if !d.auth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing path"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		if meta := r.URL.Query().Get("meta"); meta == "1" {
			node, err := d.fs.Stat(path)
			if err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			size := int64(0)
			if !node.IsDir {
				if data, err := d.fs.Read(path); err == nil {
					size = int64(len(data))
				}
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"name":     node.Name,
				"is_dir":   node.IsDir,
				"mode":     node.Mode.String(),
				"size":     size,
				"mod_time": node.ModTime.UTC().Format(time.RFC3339),
			})
			return
		}
		if list := r.URL.Query().Get("list"); list == "1" {
			withAll := r.URL.Query().Get("all") == "1"
			withDetail := r.URL.Query().Get("detail") == "1"
			names, err := d.fs.List(path)
			if err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			if !withAll {
				filtered := make([]string, 0, len(names))
				for _, n := range names {
					if strings.HasPrefix(n, ".") {
						continue
					}
					filtered = append(filtered, n)
				}
				names = filtered
			}
			if !withDetail {
				writeJSON(w, http.StatusOK, map[string]any{"items": names})
				return
			}
			type entry struct {
				Name    string `json:"name"`
				IsDir   bool   `json:"is_dir"`
				Mode    string `json:"mode"`
				Size    int64  `json:"size"`
				ModTime string `json:"mod_time"`
			}
			entries := make([]entry, 0, len(names))
			for _, n := range names {
				node, err := d.fs.Stat(stdpath.Join(path, n))
				if err != nil {
					continue
				}
				size := int64(0)
				if !node.IsDir {
					if data, err := d.fs.Read(stdpath.Join(path, n)); err == nil {
						size = int64(len(data))
					}
				}
				entries = append(entries, entry{
					Name:    n,
					IsDir:   node.IsDir,
					Mode:    node.Mode.String(),
					Size:    size,
					ModTime: node.ModTime.UTC().Format(time.RFC3339),
				})
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": entries})
			return
		}
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
			From    string `json:"from"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if body.From != "" {
			data, err := d.fs.Read(body.From)
			if err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			if dir := parentDir(path); dir != "" && dir != "/" {
				_ = d.fs.MkdirAll(dir, 0o755)
			}
			if err := d.fs.Write(path, data, 0o600); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
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
		if r.URL.Query().Get("recursive") == "1" {
			if err := d.removeRecursive(path); err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		if err := d.fs.Remove(path); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (d *Daemon) handleMkdir(w http.ResponseWriter, r *http.Request) {
	if !d.auth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	p := r.URL.Query().Get("path")
	if p == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing path"})
		return
	}
	if r.URL.Query().Get("parents") == "1" {
		if err := d.fs.MkdirAll(p, 0o755); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	} else {
		if err := d.fs.Mkdir(p, 0o755); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d *Daemon) handleRmdir(w http.ResponseWriter, r *http.Request) {
	if !d.auth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	p := r.URL.Query().Get("path")
	if p == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing path"})
		return
	}
	if err := d.fs.Remove(p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d *Daemon) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if !d.auth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	go func() {
		_ = d.Shutdown(context.Background())
		os.Exit(0)
	}()
}

func (d *Daemon) removeRecursive(p string) error {
	n, err := d.fs.Stat(p)
	if err != nil {
		return err
	}
	if !n.IsDir {
		return d.fs.Remove(p)
	}
	children, err := d.fs.List(p)
	if err != nil {
		return err
	}
	for _, c := range children {
		if err := d.removeRecursive(stdpath.Join(p, c)); err != nil {
			return err
		}
	}
	return d.fs.Remove(p)
}

func (d *Daemon) writeRuntimeState() error {
	if err := os.MkdirAll(d.cfg.RuntimeDir, 0o700); err != nil {
		return err
	}
	state := RuntimeState{
		ControlURL:   fmt.Sprintf("http://%s?token=%s", d.devAddr, d.cfg.ControlToken),
		ControlAddr:  d.devAddr,
		ControlToken: d.cfg.ControlToken,
		WebDAVAddr:   d.webdav.Addr(),
		Mountpoint:   d.cfg.MountPoint,
	}
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d.cfg.RuntimeDir, "runtime.json"), b, 0o600)
}
