// Package node implements the daemon-side logical control node that sits on top
// of a transport.Conn. It owns:
//
//   - the RPC dispatcher (WRITE/DELETE/STATUS/MANIFEST/PULL/UNMOUNT/LOCK/SET_CONFIG)
//     against the in-memory file system, and
//   - the AUTHORITATIVE grace timer: when the hub reports the vault peer went
//     offline, it starts a countdown and auto-locks (unmount + wipe) on expiry,
//     cancelling if the vault returns in time. This is policy B ("screensaver"
//     style) from the control-plane design.
//
// The grace timer lives here (not in the hub/DO) because the daemon is what
// physically enforces unmount; the DO Alarm is only a backup.
package node

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/anomalyco/valet-fs/internal/rpc"
	"github.com/anomalyco/valet-fs/internal/transport"
	"github.com/anomalyco/valet-fs/internal/vfs"
)

// Config wires the node to its file system and lock policy.
type Config struct {
	FS *vfs.MemFS
	// Grace is how long the VFS stays mounted after the vault goes offline.
	// Zero means lock immediately on disconnect.
	Grace time.Duration
	// Lock performs the actual unmount + heap wipe. Called on grace expiry and
	// on explicit UNMOUNT/LOCK requests.
	Lock func()
	// Mounted reports the current mount state for STATUS.
	Mounted func() bool
	// Serving, when set, augments STATUS with transport-backend detail so a
	// client (the app) can distinguish "unmounted + wiped" (mounted=false)
	// from "serving over WebDAV because the host has no FUSE" (mounted=true,
	// backend=webdav). Optional for backward compatibility.
	Serving func() ServeInfo
}

// ServeInfo describes which frontend is actually serving the VFS, for STATUS.
type ServeInfo struct {
	Backend       string // "fuse" | "webdav" | "none"
	FuseActive    bool   // a real kernel FUSE mount is serving
	FuseError     string // last FUSE mount error (empty when on WebDAV fallback)
	WebdavServing bool   // loopback WebDAV server is up
	WebdavAddr    string // bound WebDAV loopback address (informational)
}

// MemoryNode is the daemon-side control endpoint.
type MemoryNode struct {
	cfg  Config
	disp *rpc.Dispatcher

	mu    sync.Mutex
	conn  transport.Conn
	grace *time.Timer
}

// New builds a node and registers its handlers.
func New(cfg Config) *MemoryNode {
	n := &MemoryNode{cfg: cfg, disp: rpc.NewDispatcher()}
	n.register()
	return n
}

// Attach binds the node to a connection, routing inbound frames.
func (n *MemoryNode) Attach(c transport.Conn) {
	n.mu.Lock()
	n.conn = c
	n.mu.Unlock()
	c.OnData(n.onData)
}

type sysFrame struct {
	Sys  string `json:"sys"`
	Role string `json:"role"`
}

func (n *MemoryNode) onData(b []byte) {
	// Presence/system frames originate from the hub, not the peer.
	var sys sysFrame
	if json.Unmarshal(b, &sys) == nil && sys.Sys != "" {
		if sys.Role == "vault" {
			switch sys.Sys {
			case "peer_offline":
				n.startGrace()
			case "peer_online":
				n.cancelGrace()
			}
		}
		return
	}
	reply, isReq := n.disp.Dispatch(b)
	if isReq && reply != nil {
		n.mu.Lock()
		conn := n.conn
		n.mu.Unlock()
		if conn != nil {
			_ = conn.Send(reply)
		}
	}
}

// --- grace timer (authoritative) ---

func (n *MemoryNode) startGrace() {
	n.mu.Lock()
	if n.grace != nil {
		n.grace.Stop()
		n.grace = nil
	}
	d := n.cfg.Grace
	lock := n.cfg.Lock
	if d <= 0 {
		n.mu.Unlock()
		if lock != nil {
			lock()
		}
		return
	}
	n.grace = time.AfterFunc(d, func() {
		if lock != nil {
			lock()
		}
	})
	n.mu.Unlock()
}

func (n *MemoryNode) cancelGrace() {
	n.mu.Lock()
	if n.grace != nil {
		n.grace.Stop()
		n.grace = nil
	}
	n.mu.Unlock()
}

// ArmGrace starts the grace countdown as if the vault were offline. The reverse
// (join) flow uses this so a daemon that is never claimed does not stay mounted
// forever; a vault coming online cancels it.
func (n *MemoryNode) ArmGrace() { n.startGrace() }

// SetGrace updates the grace duration at runtime.
func (n *MemoryNode) SetGrace(d time.Duration) {
	n.mu.Lock()
	n.cfg.Grace = d
	n.mu.Unlock()
}

// --- handlers ---

func (n *MemoryNode) register() {
	fs := n.cfg.FS

	n.disp.Handle(rpc.MethodWrite, func(req rpc.Message) (map[string]any, error) {
		p, _ := req.Params["path"].(string)
		if p == "" {
			return nil, fmt.Errorf("missing path")
		}
		data, err := decodeContent(req.Params)
		if err != nil {
			return nil, err
		}
		if dir := path.Dir(p); dir != "" && dir != "/" {
			_ = fs.MkdirAll(dir, 0o755)
		}
		if err := fs.Write(p, data, 0o600); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	})

	n.disp.Handle(rpc.MethodDelete, func(req rpc.Message) (map[string]any, error) {
		p, _ := req.Params["path"].(string)
		if p == "" {
			return nil, fmt.Errorf("missing path")
		}
		if err := fs.Remove(p); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	})

	lock := func(req rpc.Message) (map[string]any, error) {
		n.cancelGrace()
		if n.cfg.Lock != nil {
			n.cfg.Lock()
		}
		return map[string]any{"locked": true}, nil
	}
	n.disp.Handle(rpc.MethodUnmount, lock)
	n.disp.Handle(rpc.MethodLock, lock)

	n.disp.Handle(rpc.MethodStatus, func(req rpc.Message) (map[string]any, error) {
		mounted := false
		if n.cfg.Mounted != nil {
			mounted = n.cfg.Mounted()
		}
		res := map[string]any{
			"mounted": mounted,
			"used":    fs.Used(),
			"version": fs.Version(),
		}
		if n.cfg.Serving != nil {
			s := n.cfg.Serving()
			res["backend"] = s.Backend
			res["serving"] = s.FuseActive || s.WebdavServing
			res["fuse"] = map[string]any{"active": s.FuseActive, "error": s.FuseError}
			res["webdav"] = map[string]any{"serving": s.WebdavServing, "addr": s.WebdavAddr}
		}
		return res, nil
	})

	n.disp.Handle(rpc.MethodManifest, func(req rpc.Message) (map[string]any, error) {
		entries := fs.Manifest()
		out := make([]map[string]any, 0, len(entries))
		for _, e := range entries {
			out = append(out, map[string]any{
				"path": e.Path, "sha": e.SHA, "size": e.Size,
				"mod_time": e.ModTime.UTC().Format(time.RFC3339Nano),
			})
		}
		return map[string]any{"version": fs.Version(), "entries": out}, nil
	})

	n.disp.Handle(rpc.MethodPull, func(req rpc.Message) (map[string]any, error) {
		paths, _ := req.Params["paths"].([]any)
		blobs := map[string]any{}
		for _, pv := range paths {
			p, _ := pv.(string)
			if p == "" {
				continue
			}
			data, err := fs.Read(p)
			if err != nil {
				continue
			}
			blobs[p] = base64.StdEncoding.EncodeToString(data)
		}
		return map[string]any{"blobs": blobs}, nil
	})

	n.disp.Handle(rpc.MethodSetConfig, func(req rpc.Message) (map[string]any, error) {
		if v, ok := req.Params["grace_seconds"]; ok {
			if secs, ok := toFloat(v); ok {
				n.SetGrace(time.Duration(secs) * time.Second)
			}
		}
		return map[string]any{"ok": true}, nil
	})
}

// decodeContent accepts either a base64 "content_b64" field or a plain
// "content" string, returning the raw bytes.
func decodeContent(params map[string]any) ([]byte, error) {
	if b64, ok := params["content_b64"].(string); ok {
		return base64.StdEncoding.DecodeString(b64)
	}
	if s, ok := params["content"].(string); ok {
		return []byte(s), nil
	}
	return nil, nil
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}
