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
	// on an explicit LOCK request.
	Lock func()
	// Unmount stops serving the VFS WITHOUT wiping the heap (the UNMOUNT RPC).
	// Distinct from Lock, which unmounts AND wipes. Optional; if nil, UNMOUNT
	// falls back to Lock for backward compatibility.
	Unmount func()
	// Remount re-establishes the VFS mount if it was torn down (after a
	// LOCK/UNMOUNT or grace auto-lock). Called when a WRITE arrives so a
	// re-push re-serves the data instead of orphaning it in an unmounted heap.
	Remount func()
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
	// When a countdown is running, the instant it fires. Zero otherwise. Kept
	// alongside the timer because time.Timer cannot be asked how much is left,
	// and callers need to see the deadline, not just that one exists.
	graceEnd time.Time
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
	// A non-sys frame is a real RPC from the vault peer, which proves it is
	// connected right now. Cancel any pending grace even if the hub's
	// peer_online presence frame was missed/never relayed (wrong session, role
	// mismatch, or a hub blip). Without this, a secret pushed by an actively
	// connected app could be wiped ~grace later purely because presence frames
	// are a separate, unreliable channel. Presence still (re)arms grace on
	// peer_offline, so "app went away -> lock" is unchanged.
	n.cancelGrace()
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
	n.graceEnd = time.Now().Add(d)
	n.mu.Unlock()
}

func (n *MemoryNode) cancelGrace() {
	n.mu.Lock()
	if n.grace != nil {
		n.grace.Stop()
		n.grace = nil
	}
	n.graceEnd = time.Time{}
	n.mu.Unlock()
}

// GraceState reports the configured window, whether a countdown is currently
// running, and how much of it is left. Without this a client can neither show
// which grace is in effect nor tell that secrets are already on a deadline.
func (n *MemoryNode) GraceState() (configured time.Duration, armed bool, remaining time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	configured = n.cfg.Grace
	if n.grace == nil || n.graceEnd.IsZero() {
		return configured, false, 0
	}
	remaining = time.Until(n.graceEnd)
	if remaining < 0 {
		remaining = 0
	}
	return configured, true, remaining
}

// ArmGrace starts the grace countdown as if the vault were offline. The reverse
// (join) flow uses this so a daemon that is never claimed does not stay mounted
// forever; a vault coming online cancels it.
func (n *MemoryNode) ArmGrace() { n.startGrace() }

// SetGrace updates the grace window at runtime. A countdown already in flight
// is restarted against the new window: otherwise raising the grace after the
// vault went offline would silently leave the old, shorter deadline armed, and
// the caller has no way to observe or undo that.
func (n *MemoryNode) SetGrace(d time.Duration) {
	n.mu.Lock()
	n.cfg.Grace = d
	rearm := n.grace != nil
	n.mu.Unlock()
	if rearm {
		// startGrace takes the same lock, so it must be called unlocked.
		n.startGrace()
	}
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
		// A write means the vault wants data served again. If a prior LOCK/UNMOUNT
		// or grace auto-lock tore the mount down, re-establish it so the re-pushed
		// secret is actually served instead of orphaned in an unmounted heap.
		if n.cfg.Remount != nil {
			n.cfg.Remount()
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

	// LOCK: unmount AND wipe the heap (deny-by-default panic / screensaver).
	n.disp.Handle(rpc.MethodLock, func(req rpc.Message) (map[string]any, error) {
		n.cancelGrace()
		if n.cfg.Lock != nil {
			n.cfg.Lock()
		}
		return map[string]any{"locked": true}, nil
	})

	// UNMOUNT: stop serving but PRESERVE the heap (distinct from LOCK). Falls back
	// to Lock if no unmount-only hook was wired, for backward compatibility.
	n.disp.Handle(rpc.MethodUnmount, func(req rpc.Message) (map[string]any, error) {
		n.cancelGrace()
		if n.cfg.Unmount != nil {
			n.cfg.Unmount()
		} else if n.cfg.Lock != nil {
			n.cfg.Lock()
		}
		return map[string]any{"unmounted": true}, nil
	})

	n.disp.Handle(rpc.MethodStatus, func(req rpc.Message) (map[string]any, error) {
		mounted := false
		if n.cfg.Mounted != nil {
			mounted = n.cfg.Mounted()
		}
		graceCfg, graceArmed, graceLeft := n.GraceState()
		res := map[string]any{
			"mounted":       mounted,
			"used":          fs.Used(),
			"version":       fs.Version(),
			"grace_seconds": int64(graceCfg / time.Second),
			"grace_armed":   graceArmed,
		}
		if graceArmed {
			res["grace_remaining_seconds"] = int64(graceLeft / time.Second)
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
