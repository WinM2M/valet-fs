// Package ws implements transport.Conn over a WebSocket connection to a session
// hub (the Cloudflare Durable Object in production, or the Go internal/hub in
// tests/self-host). Both the daemon and the vault connect OUTBOUND to the hub,
// which removes the NAT-traversal/TURN problems of the WebRTC path.
package ws

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"

	"github.com/anomalyco/valet-fs/internal/rpc"
)

// allowInsecure permits a plaintext hub on a non-loopback host. Off by default.
var allowInsecure bool

// SetAllowInsecure opts in to talking to a hub over plain HTTP. Only a
// deliberate choice should turn this on; see checkHubURL for what it costs.
func SetAllowInsecure(v bool) { allowInsecure = v }

// checkHubURL refuses a hub address that would put the session token on the
// wire in the clear. The token is carried in the /ws/connect query string, and
// whoever reads it can join the session as that role — as the vault, that means
// reading the entire vault with MANIFEST and PULL.
//
// Loopback is exempt: `valetfs hub` and the tests run there, and there is no
// network to eavesdrop on.
func checkHubURL(hubURL string) error {
	u, err := url.Parse(hubURL)
	if err != nil {
		return fmt.Errorf("hub url %q: %w", hubURL, err)
	}
	switch u.Scheme {
	case "https", "wss":
		return nil
	case "http", "ws":
	default:
		return fmt.Errorf("hub url %q: unsupported scheme %q", hubURL, u.Scheme)
	}
	if host := u.Hostname(); host == "localhost" {
		return nil
	} else if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if allowInsecure {
		return nil
	}
	return fmt.Errorf("refusing to reach hub %s over plain HTTP: the session token "+
		"travels in the URL, and anyone who reads it can join as the vault and pull "+
		"every secret (use https, or pass --insecure-signaling to accept the risk)", hubURL)
}

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

// NewClaimSecret mints the credential that authorises claiming a session.
//
// It exists so the session id can go back to being what it looks like: a
// routing identifier, printed to a terminal and carried through logs without
// consequence. The secret goes only where a person carries it — inside the
// pairing QR, or inside a connection key — which is what lets a daemon treat
// "somebody scanned my screen" as evidence rather than a hope.
func NewClaimSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DialDaemon creates a new session on the hub and connects as the daemon role.
// daemonPubB64 (may be empty) is the X25519 public key published for E2EE.
// claimSecret (may be empty for legacy behaviour) gates who may claim it.
// It returns the connection (not yet started) and the session id.
func DialDaemon(hubURL, daemonPubB64, pubV2B64, claimSecret string) (*Conn, string, error) {
	if err := checkHubURL(hubURL); err != nil {
		return nil, "", err
	}
	var resp struct {
		SessionID   string `json:"session_id"`
		DaemonToken string `json:"daemon_token"`
	}
	body := map[string]any{"role": "daemon", "init": true, "versions": rpc.Supported}
	if daemonPubB64 != "" {
		body["pub"] = daemonPubB64
	}
	if pubV2B64 != "" {
		body["pub_v2"] = pubV2B64
	}
	if claimSecret != "" {
		body["claim_secret"] = claimSecret
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
	if err := checkHubURL(hubURL); err != nil {
		return nil, err
	}
	c, err := dialWS(hubURL, sessionID, "daemon", token)
	if err != nil {
		return nil, err
	}
	c.sid, c.token = sessionID, token
	return c, nil
}

// JoinDaemon connects to an EXISTING, app-provisioned session as the daemon
// (reverse flow). Same wire path as ReconnectDaemon; named for clarity.
func JoinDaemon(hubURL, sessionID, token string) (*Conn, error) {
	return ReconnectDaemon(hubURL, sessionID, token)
}

// PublishPub uploads the daemon's public keys to an existing session. pubB64 is
// the v1 X25519 key; pubV2B64 is the v2 Noise static key. Both are published so
// a client can open either version without a second round trip.
func PublishPub(hubURL, sessionID, token, pubB64, pubV2B64 string) error {
	if err := checkHubURL(hubURL); err != nil {
		return err
	}
	// The version list travels with the pubkeys so a client learns what this
	// daemon speaks before it opens a socket. It is hub-supplied and therefore
	// not trusted; the daemon repeats it over the encrypted channel in STATUS
	// so a client can catch a hub that edited it.
	body, _ := json.Marshal(map[string]any{
		"pub": pubB64, "pub_v2": pubV2B64, "versions": rpc.Supported,
	})
	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/ws/sessions/%s/pub", hubURL, sessionID),
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Valet-Role-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("publish pub: %s", resp.Status)
	}
	return nil
}

// DialController claims an existing session and connects as the vault role. It
// also returns the daemon's published X25519 public key (base64; may be empty
// if the daemon did not enable E2EE) and the protocol versions the hub says the
// daemon supports. Both come from the hub and neither is trusted on its own.
func DialController(hubURL, sessionID, claimSecret string) (*Conn, string, []int, error) {
	if err := checkHubURL(hubURL); err != nil {
		return nil, "", nil, err
	}
	var resp struct {
		ControllerToken string `json:"controller_token"`
		DaemonPub       string `json:"daemon_pub"`
		DaemonPubV2     string `json:"daemon_pub_v2"`
		Versions        []int  `json:"versions"`
	}
	if err := postJSONWithHeader(
		fmt.Sprintf("%s/ws/sessions/%s/claim", hubURL, sessionID),
		"X-Valet-Claim-Secret", claimSecret, nil, &resp); err != nil {
		return nil, "", nil, err
	}
	c, err := dialWS(hubURL, sessionID, "vault", resp.ControllerToken)
	if err != nil {
		return nil, "", nil, err
	}
	return c, resp.DaemonPub, resp.Versions, nil
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
	return postJSONWithHeader(endpoint, "", "", body, out)
}

func postJSONWithHeader(endpoint, header, value string, body any, out any) error {
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
	if header != "" && value != "" {
		req.Header.Set(header, value)
	}
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
