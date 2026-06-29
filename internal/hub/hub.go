// Package hub implements a minimal WebSocket session hub that mirrors the
// Cloudflare Durable Object contract used by ValetFS' control plane:
//
//   - one logical session per id, addressable by both peers
//   - each peer connects OUTBOUND (NAT-friendly; no inbound ports)
//   - the hub relays opaque app frames between the daemon and vault roles
//   - the hub emits presence frames ({"sys":"peer_online"|"peer_offline"})
//     so the daemon can drive its grace timer
//
// It is used as the in-process reference hub for automated local tests, and is
// also runnable as a self-hosted Go alternative to the Durable Object.
package hub

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/websocket"
)

const (
	roleDaemon = "daemon"
	roleVault  = "vault"
)

// presence is the system frame the hub pushes to a peer about the other peer.
type presence struct {
	Sys  string `json:"sys"`
	Role string `json:"role"`
}

type session struct {
	mu        sync.Mutex
	id        string
	daemonTok string
	vaultTok  string
	conns     map[string]*websocket.Conn // role -> conn
}

func (s *session) other(role string) string {
	if role == roleDaemon {
		return roleVault
	}
	return roleDaemon
}

// Server is an http.Handler exposing the hub endpoints.
type Server struct {
	mu       sync.Mutex
	sessions map[string]*session
	idgen    func() string
}

// New returns an empty hub.
func New() *Server {
	return &Server{sessions: map[string]*session{}, idgen: randomHex}
}

func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ServeHTTP routes:
//
//	POST /sessions            {role:"daemon",init:true} -> {session_id,daemon_token}
//	POST /sessions/<id>/claim                            -> {controller_token}
//	GET  /ws?sid=&role=&token=                           -> websocket upgrade
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/ws/sessions" && r.Method == http.MethodPost:
		s.handleCreate(w, r)
	case strings.HasPrefix(r.URL.Path, "/ws/sessions/") && strings.HasSuffix(r.URL.Path, "/claim") && r.Method == http.MethodPost:
		s.handleClaim(w, r)
	case r.URL.Path == "/ws/connect":
		websocket.Handler(s.handleWS).ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Role string `json:"role"`
		Init bool   `json:"init"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Role != roleDaemon {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role must be daemon"})
		return
	}
	sess := &session{id: s.idgen(), daemonTok: randomHex(), conns: map[string]*websocket.Conn{}}
	s.mu.Lock()
	s.sessions[sess.id] = sess
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"session_id": sess.id, "daemon_token": sess.daemonTok})
}

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/ws/sessions/"), "/claim")
	s.mu.Lock()
	sess := s.sessions[id]
	s.mu.Unlock()
	if sess == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such session"})
		return
	}
	sess.mu.Lock()
	if sess.vaultTok == "" {
		sess.vaultTok = randomHex()
	}
	tok := sess.vaultTok
	sess.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"controller_token": tok})
}

func (s *Server) handleWS(ws *websocket.Conn) {
	q := ws.Request().URL.Query()
	id, role, tok := q.Get("sid"), q.Get("role"), q.Get("token")
	s.mu.Lock()
	sess := s.sessions[id]
	s.mu.Unlock()
	if sess == nil || (role != roleDaemon && role != roleVault) {
		return
	}

	// Authenticate by role token.
	sess.mu.Lock()
	want := sess.daemonTok
	if role == roleVault {
		want = sess.vaultTok
	}
	if want == "" || tok != want {
		sess.mu.Unlock()
		return
	}
	sess.conns[role] = ws
	otherConn := sess.conns[sess.other(role)]
	sess.mu.Unlock()

	// Presence: tell the existing peer we're online, and tell us about it.
	if otherConn != nil {
		sendPresence(otherConn, "peer_online", role)
		sendPresence(ws, "peer_online", sess.other(role))
	}

	defer func() {
		sess.mu.Lock()
		if sess.conns[role] == ws {
			delete(sess.conns, role)
		}
		peer := sess.conns[sess.other(role)]
		sess.mu.Unlock()
		if peer != nil {
			sendPresence(peer, "peer_offline", role)
		}
	}()

	// Relay loop: forward every frame verbatim to the other role.
	for {
		var data []byte
		if err := websocket.Message.Receive(ws, &data); err != nil {
			return
		}
		sess.mu.Lock()
		peer := sess.conns[sess.other(role)]
		sess.mu.Unlock()
		if peer != nil {
			_ = websocket.Message.Send(peer, data)
		}
	}
}

func sendPresence(ws *websocket.Conn, sys, role string) {
	b, _ := json.Marshal(presence{Sys: sys, Role: role})
	_ = websocket.Message.Send(ws, b)
}
