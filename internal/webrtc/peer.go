// Package webrtc wraps pion/webrtc to expose ValetFS' P2P data channel and
// handles QR-code-based session bootstrap against a Cloudflare Worker.
package webrtc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mdp/qrterminal/v3"
	"github.com/pion/ice/v2"
	"github.com/pion/webrtc/v3"
)

// Peer holds the active PeerConnection and the bi-directional DataChannel.
type Peer struct {
	mu      sync.Mutex
	pc      *webrtc.PeerConnection
	dc      *webrtc.DataChannel
	role    string
	onICE   func(webrtc.ICECandidateInit)
	onData  func([]byte)
	onOpen  func()
	onClose func()
}

var verboseLogging bool

// SetVerbose enables (-v) diagnostic logging across all peers.
func SetVerbose(v bool) { verboseLogging = v }

func vlogf(format string, a ...any) {
	if verboseLogging {
		log.Printf("webrtc: "+format, a...)
	}
}

// defaultICEServers returns the bootstrap STUN list used before any
// signaling-provided TURN credentials are merged in.
func defaultICEServers() []webrtc.ICEServer {
	return []webrtc.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
	}
}

// buildAPI constructs a webrtc.API with a SettingEngine that enables both
// UDP and TCP ICE candidate gathering. Without explicitly listing TCP4/TCP6
// network types here pion will not gather TURN-over-TCP relay candidates,
// which are essential when the local network blocks UDP.
func buildAPI() *webrtc.API {
	s := webrtc.SettingEngine{}
	s.SetNetworkTypes([]webrtc.NetworkType{
		webrtc.NetworkTypeUDP4,
		webrtc.NetworkTypeUDP6,
		webrtc.NetworkTypeTCP4,
		webrtc.NetworkTypeTCP6,
	})
	// Provide a passive TCP mux so the gatherer can produce active TCP
	// candidates as well; required for turn:...?transport=tcp relay flow.
	if tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4zero, Port: 0}); err == nil {
		s.SetICETCPMux(webrtc.NewICETCPMux(nil, tcpListener, 8))
	}
	// Disable mDNS so candidates carry routable addresses (mDNS .local
	// names confuse strict-NAT TURN-only paths).
	s.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	return webrtc.NewAPI(webrtc.WithSettingEngine(s))
}

var sharedAPI = buildAPI()

// newPeer constructs a PeerConnection with the provided ICE servers baked in
// at construction time. This is critical: pion only gathers relay candidates
// from servers known at gatherer-creation, so TURN must be merged here, not
// via SetConfiguration later.
func newPeer(role string, servers []webrtc.ICEServer, relayOnly bool) (*Peer, error) {
	if len(servers) == 0 {
		servers = defaultICEServers()
	}
	cfg := webrtc.Configuration{ICEServers: servers}
	if relayOnly {
		cfg.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	pc, err := sharedAPI.NewPeerConnection(cfg)
	if err != nil {
		return nil, err
	}
	p := &Peer{pc: pc, role: role}
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		vlogf("ice state=%s role=%s", s.String(), role)
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		vlogf("peer state=%s role=%s", s.String(), role)
		if s == webrtc.PeerConnectionStateConnected {
			p.logSelectedPair()
		}
	})
	return p, nil
}

// New retains the old zero-config constructor for callers that have not yet
// migrated to the ICE-aware path. Prefer NewDaemon/NewController.
func New() (*Peer, error) { return newPeer("daemon", nil, false) }

func fetchICEServers(signalingURL, sessionID, token string) ([]webrtc.ICEServer, error) {
	req, _ := http.NewRequest(http.MethodGet, strings.TrimRight(signalingURL, "/")+"/sessions/"+sessionID+"/turn", nil)
	req.Header.Set("X-Valet-Role-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("turn fetch failed: %s", strings.TrimSpace(string(b)))
	}
	var out struct {
		IceServers []struct {
			URLs       any    `json:"urls"`
			Username   string `json:"username"`
			Credential string `json:"credential"`
		} `json:"iceServers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	servers := normalizeICEServers(out.IceServers)
	return servers, nil
}

// normalizeICEServers converts the loosely-typed signaling representation
// (urls may be a string or array, credential fields optional) into pion's
// strict ICEServer struct. Empty entries are dropped.
func normalizeICEServers(in []struct {
	URLs       any    `json:"urls"`
	Username   string `json:"username"`
	Credential string `json:"credential"`
}) []webrtc.ICEServer {
	servers := make([]webrtc.ICEServer, 0, len(in))
	for _, s := range in {
		urls := make([]string, 0)
		switch v := s.URLs.(type) {
		case string:
			urls = append(urls, v)
		case []any:
			for _, x := range v {
				if u, ok := x.(string); ok {
					urls = append(urls, u)
				}
			}
		}
		if len(urls) == 0 {
			continue
		}
		es := webrtc.ICEServer{URLs: urls}
		if s.Username != "" || s.Credential != "" {
			es.Username = s.Username
			es.Credential = s.Credential
			es.CredentialType = webrtc.ICECredentialTypePassword
		}
		servers = append(servers, es)
	}
	return servers
}

// fetchICEServersBootstrap retrieves ICE servers without a session/token. Used
// before NewPeerConnection so that TURN credentials can be merged in at
// construction time. For now it falls back to STUN-only since the existing
// /turn endpoint requires a role token; the daemon path obtains TURN after
// session creation via reset (see NewDaemonWithICE).
func fetchICEServersBootstrap(signalingURL string) []webrtc.ICEServer {
	_ = signalingURL
	return defaultICEServers()
}

// NewDaemon creates an offerer-side peer for `valetfs serve`. The peer is
// constructed with bootstrap STUN servers; TURN credentials are fetched after
// the session id is known and the peer is rebuilt via WithICE.
func NewDaemon() (*Peer, error) { return newPeer("daemon", defaultICEServers(), false) }

// NewController creates an answerer-side peer for `valetfs vault pair`.
func NewController() (*Peer, error) {
	p, err := newPeer("controller", defaultICEServers(), false)
	if err != nil {
		return nil, err
	}
	p.attachOnDataChannel()
	return p, nil
}

// rebuildWithICE closes the existing PeerConnection and recreates it with
// the supplied ICE servers baked in. Must be called before CreateOffer or
// AcceptOfferAndAnswer to ensure relay candidates are gathered.
func (p *Peer) rebuildWithICE(servers []webrtc.ICEServer, relayOnly bool) error {
	if p.pc != nil {
		_ = p.pc.Close()
	}
	cfg := webrtc.Configuration{ICEServers: servers}
	if relayOnly {
		cfg.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	pc, err := sharedAPI.NewPeerConnection(cfg)
	if err != nil {
		return err
	}
	p.pc = pc
	role := p.role
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		vlogf("ice state=%s role=%s", s.String(), role)
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		vlogf("peer state=%s role=%s", s.String(), role)
		if s == webrtc.PeerConnectionStateConnected {
			p.logSelectedPair()
		}
	})
	if p.role == "controller" {
		p.attachOnDataChannel()
	}
	if p.onICE != nil {
		fn := p.onICE
		p.pc.OnICECandidate(func(c *webrtc.ICECandidate) {
			if c == nil {
				return
			}
			fn(c.ToJSON())
		})
	}
	return nil
}

func (p *Peer) attachOnDataChannel() {
	p.pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		p.mu.Lock()
		p.dc = dc
		p.mu.Unlock()
		dc.OnOpen(func() {
			if p.onOpen != nil {
				p.onOpen()
			}
		})
		dc.OnClose(func() {
			if p.onClose != nil {
				p.onClose()
			}
		})
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if p.onData != nil {
				p.onData(msg.Data)
			}
		})
	})
}

// logSelectedPair walks the stats report and prints the negotiated candidate
// pair (host/srflx/relay + addresses). Invaluable for diagnosing why a
// particular network failed P2P.
func (p *Peer) logSelectedPair() {
	if !verboseLogging || p.pc == nil {
		return
	}
	stats := p.pc.GetStats()
	var (
		pairID    string
		localID   string
		remoteID  string
		localStr  string
		remoteStr string
	)
	for _, s := range stats {
		if cp, ok := s.(webrtc.ICECandidatePairStats); ok {
			if cp.Nominated && cp.State == webrtc.StatsICECandidatePairStateSucceeded {
				pairID = cp.ID
				localID = cp.LocalCandidateID
				remoteID = cp.RemoteCandidateID
				break
			}
		}
	}
	for _, s := range stats {
		if c, ok := s.(webrtc.ICECandidateStats); ok {
			if c.ID == localID {
				localStr = fmt.Sprintf("%s/%s:%d (%s)", c.CandidateType, c.IP, c.Port, c.Protocol)
			}
			if c.ID == remoteID {
				remoteStr = fmt.Sprintf("%s/%s:%d (%s)", c.CandidateType, c.IP, c.Port, c.Protocol)
			}
		}
	}
	if pairID != "" {
		vlogf("selected pair role=%s local=%s remote=%s", p.role, localStr, remoteStr)
	} else {
		vlogf("selected pair role=%s not-found", p.role)
	}
}

// OnData registers a callback invoked for each inbound DataChannel message.
func (p *Peer) OnData(fn func([]byte)) { p.onData = fn }

// OnOpen registers a callback invoked once the DataChannel transitions to open.
func (p *Peer) OnOpen(fn func()) { p.onOpen = fn }

// OnClose registers a callback invoked when the DataChannel is closed.
func (p *Peer) OnClose(fn func()) { p.onClose = fn }

// OnICECandidate registers a callback for local ICE candidates.
func (p *Peer) OnICECandidate(fn func(webrtc.ICECandidateInit)) {
	p.onICE = fn
	p.pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil || p.onICE == nil {
			return
		}
		p.onICE(c.ToJSON())
	})
}

// AddRemoteCandidate appends an ICE candidate from signaling.
func (p *Peer) AddRemoteCandidate(c webrtc.ICECandidateInit) error {
	return p.pc.AddICECandidate(c)
}

// CreateOffer creates the "valetfs" DataChannel and returns the local
// description as soon as SetLocalDescription completes. Trickle ICE
// candidates are delivered out-of-band via the signaling /candidates
// endpoint; we deliberately do NOT wait for gathering to complete.
func (p *Peer) CreateOffer() (webrtc.SessionDescription, error) {
	dc, err := p.pc.CreateDataChannel("valetfs", nil)
	if err != nil {
		return webrtc.SessionDescription{}, err
	}
	p.mu.Lock()
	p.dc = dc
	p.mu.Unlock()

	dc.OnOpen(func() {
		if p.onOpen != nil {
			p.onOpen()
		}
	})
	dc.OnClose(func() {
		if p.onClose != nil {
			p.onClose()
		}
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if p.onData != nil {
			p.onData(msg.Data)
		}
	})

	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		return offer, err
	}
	if err := p.pc.SetLocalDescription(offer); err != nil {
		return offer, err
	}
	return *p.pc.LocalDescription(), nil
}

// AcceptAnswer applies the remote SDP answer.
func (p *Peer) AcceptAnswer(answer webrtc.SessionDescription) error {
	return p.pc.SetRemoteDescription(answer)
}

// AcceptOfferAndAnswer applies remote offer and returns local answer.
// As with CreateOffer, gathering proceeds in the background and candidates
// are trickled separately.
func (p *Peer) AcceptOfferAndAnswer(offer webrtc.SessionDescription) (webrtc.SessionDescription, error) {
	if err := p.pc.SetRemoteDescription(offer); err != nil {
		return webrtc.SessionDescription{}, err
	}
	answer, err := p.pc.CreateAnswer(nil)
	if err != nil {
		return webrtc.SessionDescription{}, err
	}
	if err := p.pc.SetLocalDescription(answer); err != nil {
		return webrtc.SessionDescription{}, err
	}
	return *p.pc.LocalDescription(), nil
}

// Send writes raw bytes over the DataChannel.
func (p *Peer) Send(b []byte) error {
	p.mu.Lock()
	dc := p.dc
	p.mu.Unlock()
	if dc == nil {
		return fmt.Errorf("webrtc: data channel not ready")
	}
	return dc.Send(b)
}

// Close tears down the peer connection.
func (p *Peer) Close() error {
	if p.pc == nil {
		return nil
	}
	return p.pc.Close()
}

// Bootstrap is the high-level helper used by the daemon (offerer) side. It
// creates a session, fetches TURN credentials, rebuilds the PeerConnection
// with those credentials baked in, posts the offer, prints a QR code, then
// long-polls for the controller's answer while exchanging trickle candidates.
func (p *Peer) Bootstrap(signalingURL string) error {
	if signalingURL == "" {
		return fmt.Errorf("webrtc: signaling URL is empty")
	}
	signalingURL = strings.TrimRight(signalingURL, "/")

	vlogf("bootstrap start signaling=%s", signalingURL)

	// Step 1: allocate a session id + daemon token + iceServers in one
	// round-trip. The /sessions endpoint in init mode does NOT require an
	// offer; this lets us build the PeerConnection with TURN credentials
	// baked in from the very first ICE gathering pass, so every candidate
	// (host/srflx/relay) is emitted under a single, stable ufrag/pwd.
	initPayload, _ := json.Marshal(map[string]any{"role": "daemon", "init": true})
	resp, err := http.Post(signalingURL+"/sessions", "application/json", bytes.NewReader(initPayload))
	if err != nil {
		return fmt.Errorf("post session init: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var created struct {
		SessionID  string `json:"session_id"`
		Token      string `json:"daemon_token"`
		ICEServers []struct {
			URLs       any    `json:"urls"`
			Username   string `json:"username"`
			Credential string `json:"credential"`
		} `json:"iceServers"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		return fmt.Errorf("decode session: %w", err)
	}
	if created.SessionID == "" {
		return fmt.Errorf("signaling did not return a session id")
	}
	vlogf("session created id=%s", created.SessionID)

	// Step 2: rebuild peer with the iceServers we just received. If the
	// init response omitted them (legacy worker), fall back to the
	// authenticated /turn endpoint.
	iceServers := normalizeICEServers(created.ICEServers)
	if len(iceServers) == 0 {
		if servers, err := fetchICEServers(signalingURL, created.SessionID, created.Token); err == nil && len(servers) > 0 {
			iceServers = servers
		} else {
			iceServers = defaultICEServers()
		}
	}
	vlogf("turn fetched count=%d", len(iceServers))
	if err := p.rebuildWithICE(iceServers, false); err != nil {
		return fmt.Errorf("rebuild with ice: %w", err)
	}

	// Step 3: register the candidate exchange BEFORE creating the offer so
	// that we capture every gathered candidate from t=0.
	if err := p.startCandidateExchange(signalingURL, created.SessionID, created.Token, "daemon"); err != nil {
		return err
	}
	vlogf("candidate exchange started role=daemon")

	// Step 4: create the offer on the TURN-aware peer and publish it.
	realOffer, err := p.CreateOffer()
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}
	if err := postOfferUpdate(signalingURL, created.SessionID, created.Token, realOffer); err != nil {
		return fmt.Errorf("post offer: %w", err)
	}

	qrterminal.GenerateHalfBlock(
		fmt.Sprintf("valetfs://pair?session=%s&url=%s", created.SessionID, signalingURL),
		qrterminal.L, os.Stdout)
	fmt.Printf("Session ID: %s\n", created.SessionID)
	fmt.Println("Scan with the ValetFS mobile app to pair.")

	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, signalingURL+"/sessions/"+created.SessionID+"/answer", nil)
		req.Header.Set("X-Valet-Role-Token", created.Token)
		ar, err := http.DefaultClient.Do(req)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		ab, _ := io.ReadAll(ar.Body)
		ar.Body.Close()
		if ar.StatusCode == http.StatusOK && len(ab) > 0 {
			vlogf("answer received for session=%s", created.SessionID)
			var wrap struct {
				Answer webrtc.SessionDescription `json:"answer"`
			}
			if err := json.Unmarshal(ab, &wrap); err != nil {
				return fmt.Errorf("decode answer: %w", err)
			}
			return p.AcceptAnswer(wrap.Answer)
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("webrtc: timed out waiting for mobile pairing")
}

func postOfferUpdate(signalingURL, sessionID, token string, offer webrtc.SessionDescription) error {
	body, _ := json.Marshal(map[string]any{"offer": offer})
	req, _ := http.NewRequest(http.MethodPost, signalingURL+"/sessions/"+sessionID+"/offer", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Valet-Role-Token", token)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		b, _ := io.ReadAll(r.Body)
		return fmt.Errorf("%s", strings.TrimSpace(string(b)))
	}
	return nil
}

// Join claims a daemon session as controller, fetches TURN, rebuilds the
// peer with TURN baked in, exchanges SDP answer and connects.
func (p *Peer) Join(signalingURL, sessionID string) error {
	if signalingURL == "" || sessionID == "" {
		return fmt.Errorf("webrtc: signaling URL and session ID are required")
	}
	signalingURL = strings.TrimRight(signalingURL, "/")

	vlogf("join start signaling=%s session=%s", signalingURL, sessionID)
	claimBody, _ := json.Marshal(map[string]any{"role": "controller"})
	resp, err := http.Post(signalingURL+"/sessions/"+sessionID+"/claim", "application/json", bytes.NewReader(claimBody))
	if err != nil {
		return fmt.Errorf("claim session: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("claim failed: %s", strings.TrimSpace(string(b)))
	}
	var claimed struct {
		ControllerToken string                    `json:"controller_token"`
		Offer           webrtc.SessionDescription `json:"offer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&claimed); err != nil {
		return fmt.Errorf("decode claim: %w", err)
	}
	if claimed.ControllerToken == "" {
		return fmt.Errorf("missing controller token")
	}
	vlogf("claim success session=%s", sessionID)

	// Fetch TURN and rebuild the peer BEFORE producing the answer so relay
	// candidates are actually gathered.
	iceServers := defaultICEServers()
	if servers, err := fetchICEServers(signalingURL, sessionID, claimed.ControllerToken); err == nil && len(servers) > 0 {
		iceServers = servers
		vlogf("turn fetched count=%d", len(servers))
	} else if err != nil {
		vlogf("turn fetch skipped: %v", err)
	}
	if err := p.rebuildWithICE(iceServers, false); err != nil {
		return fmt.Errorf("rebuild with ice: %w", err)
	}

	if err := p.startCandidateExchange(signalingURL, sessionID, claimed.ControllerToken, "controller"); err != nil {
		return err
	}
	vlogf("candidate exchange started role=controller")

	answer, err := p.AcceptOfferAndAnswer(claimed.Offer)
	if err != nil {
		return fmt.Errorf("create answer: %w", err)
	}

	ab, _ := json.Marshal(map[string]any{"answer": answer})
	req, _ := http.NewRequest(http.MethodPost, signalingURL+"/sessions/"+sessionID+"/answer", bytes.NewReader(ab))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Valet-Role-Token", claimed.ControllerToken)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("post answer: %w", err)
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		b, _ := io.ReadAll(r.Body)
		return fmt.Errorf("post answer failed: %s", strings.TrimSpace(string(b)))
	}
	vlogf("answer posted session=%s", sessionID)

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		state := p.pc.ConnectionState()
		if state == webrtc.PeerConnectionStateConnected {
			vlogf("peer connected session=%s", sessionID)
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("webrtc: timed out waiting for data channel open")
}

func (p *Peer) startCandidateExchange(signalingURL, sessionID, token, role string) error {
	p.OnICECandidate(func(c webrtc.ICECandidateInit) {
		ct := "unknown"
		if c.Candidate != "" {
			parts := strings.Fields(c.Candidate)
			for i, x := range parts {
				if x == "typ" && i+1 < len(parts) {
					ct = parts[i+1]
					break
				}
			}
		}
		vlogf("local candidate gathered role=%s type=%s", role, ct)
		body, _ := json.Marshal(map[string]any{"candidates": []webrtc.ICECandidateInit{c}})
		req, _ := http.NewRequest(http.MethodPost, signalingURL+"/sessions/"+sessionID+"/candidates", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Valet-Role-Token", token)
		_, _ = http.DefaultClient.Do(req)
	})

	go func() {
		since := 0
		for {
			if p.pc.ConnectionState() == webrtc.PeerConnectionStateClosed {
				return
			}
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/sessions/%s/candidates?since=%d", signalingURL, sessionID, since), nil)
			req.Header.Set("X-Valet-Role-Token", token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				time.Sleep(400 * time.Millisecond)
				continue
			}
			if resp.StatusCode >= 300 {
				resp.Body.Close()
				time.Sleep(500 * time.Millisecond)
				continue
			}
			var out struct {
				Candidates []webrtc.ICECandidateInit `json:"candidates"`
				Next       int                       `json:"next"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			for _, c := range out.Candidates {
				ct := "unknown"
				if c.Candidate != "" {
					parts := strings.Fields(c.Candidate)
					for i, x := range parts {
						if x == "typ" && i+1 < len(parts) {
							ct = parts[i+1]
							break
						}
					}
				}
				vlogf("remote candidate received role=%s type=%s", role, ct)
				_ = p.AddRemoteCandidate(c)
			}
			since = out.Next
			time.Sleep(200 * time.Millisecond)
		}
	}()
	return nil
}
