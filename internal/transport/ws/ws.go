// Package ws implements transport.Conn over a WebSocket connection to a session
// hub (the Cloudflare Durable Object in production, or the Go internal/hub in
// tests/self-host). Both the daemon and the vault connect OUTBOUND to the hub,
// which removes the NAT-traversal/TURN problems of the WebRTC path.
package ws

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// Conn adapts a websocket.Conn to the transport.Conn interface.
type Conn struct {
	ws *websocket.Conn

	sid   string // session id (daemon role, for reconnect)
	token string // daemon role token (for reconnect)

	mu        sync.Mutex
	onData    func([]byte)
	onOpen    func()
	onClose   func()
	started   bool
	done      chan struct{}
	closeOnce sync.Once
}

// OnData registers the inbound-frame callback.
func (c *Conn) OnData(f func([]byte)) { c.mu.Lock(); c.onData = f; c.mu.Unlock() }

// OnOpen registers the open callback (fired by Start).
func (c *Conn) OnOpen(f func()) { c.mu.Lock(); c.onOpen = f; c.mu.Unlock() }

// OnClose registers the close callback.
func (c *Conn) OnClose(f func()) { c.mu.Lock(); c.onClose = f; c.mu.Unlock() }

// Send transmits one frame.
func (c *Conn) Send(b []byte) error { return websocket.Message.Send(c.ws, b) }

// Close tears the socket down.
func (c *Conn) Close() error { c.stop(); return c.ws.Close() }

// stop signals background goroutines (keepalive) to exit, once.
func (c *Conn) stop() {
	c.closeOnce.Do(func() {
		if c.done != nil {
			close(c.done)
		}
	})
}

// keepalive sends a tiny frame periodically so an idle daemon<->hub WebSocket
// is not closed by the edge (Cloudflare) as inactive. The peer ignores it.
func (c *Conn) keepalive() {
	t := time.NewTicker(25 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			if err := websocket.Message.Send(c.ws, []byte(`{"sys":"ka"}`)); err != nil {
				return
			}
		}
	}
}

// Start begins the read loop and fires OnOpen. Call after registering handlers.
func (c *Conn) Start() {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return
	}
	c.started = true
	onOpen := c.onOpen
	c.mu.Unlock()
	if onOpen != nil {
		onOpen()
	}
	go c.readLoop()
	go c.keepalive()
}

func (c *Conn) readLoop() {
	for {
		var data []byte
		if err := websocket.Message.Receive(c.ws, &data); err != nil {
			c.stop()
			c.mu.Lock()
			onClose := c.onClose
			c.mu.Unlock()
			if onClose != nil {
				onClose()
			}
			return
		}
		c.mu.Lock()
		onData := c.onData
		c.mu.Unlock()
		if onData != nil {
			onData(data)
		}
	}
}

// DialDaemon creates a new session on the hub and connects as the daemon role.
// daemonPubB64 (may be empty) is the X25519 public key published for E2EE.
// It returns the connection (not yet started), the session id, and the token.
func DialDaemon(hubURL, daemonPubB64 string) (*Conn, string, error) {
	var resp struct {
		SessionID   string `json:"session_id"`
		DaemonToken string `json:"daemon_token"`
	}
	body := map[string]any{"role": "daemon", "init": true}
	if daemonPubB64 != "" {
		body["pub"] = daemonPubB64
	}
	if err := postJSON(hubURL+"/ws/sessions", body, &resp); err != nil {
		return nil, "", err
	}
	c, err := dialWS(hubURL, resp.SessionID, "daemon", resp.DaemonToken)
	if err != nil {
		return nil, "", err
	}
	c.sid, c.token = resp.SessionID, resp.DaemonToken
	return c, resp.SessionID, nil
}

// SessionID returns the daemon session id (set for DialDaemon connections).
func (c *Conn) SessionID() string { return c.sid }

// Token returns the daemon role token (set for DialDaemon connections).
func (c *Conn) Token() string { return c.token }

// ReconnectDaemon re-opens a daemon WebSocket to an EXISTING session without
// allocating a new one. It fails if the session no longer exists on the hub
// (e.g. the vault deleted it), which the caller uses to trigger a self-lock.
func ReconnectDaemon(hubURL, sessionID, token string) (*Conn, error) {
	c, err := dialWS(hubURL, sessionID, "daemon", token)
	if err != nil {
		return nil, err
	}
	c.sid, c.token = sessionID, token
	return c, nil
}

// DialController claims an existing session and connects as the vault role.
// It also returns the daemon's published X25519 public key (base64; may be
// empty if the daemon did not enable E2EE).
func DialController(hubURL, sessionID string) (*Conn, string, error) {
	var resp struct {
		ControllerToken string `json:"controller_token"`
		DaemonPub       string `json:"daemon_pub"`
	}
	if err := postJSON(fmt.Sprintf("%s/ws/sessions/%s/claim", hubURL, sessionID), nil, &resp); err != nil {
		return nil, "", err
	}
	c, err := dialWS(hubURL, sessionID, "vault", resp.ControllerToken)
	if err != nil {
		return nil, "", err
	}
	return c, resp.DaemonPub, nil
}

func dialWS(hubURL, sid, role, token string) (*Conn, error) {
	wsURL := toWSScheme(hubURL) + "/ws/connect?sid=" + url.QueryEscape(sid) +
		"&role=" + url.QueryEscape(role) + "&token=" + url.QueryEscape(token)
	origin := strings.TrimSuffix(hubURL, "/")
	c, err := websocket.Dial(wsURL, "", origin)
	if err != nil {
		return nil, err
	}
	return &Conn{ws: c, done: make(chan struct{})}, nil
}

func toWSScheme(httpURL string) string {
	if strings.HasPrefix(httpURL, "https://") {
		return "wss://" + strings.TrimPrefix(httpURL, "https://")
	}
	return "ws://" + strings.TrimPrefix(httpURL, "http://")
}

func postJSON(endpoint string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hub %s: %s: %s", endpoint, resp.Status, string(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
