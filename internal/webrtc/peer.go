// Package webrtc wraps pion/webrtc to expose ValetFS' P2P data channel and
// handles QR-code-based session bootstrap against a Cloudflare Worker.
package webrtc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mdp/qrterminal/v3"
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

func SetVerbose(v bool) { verboseLogging = v }

func vlogf(format string, a ...any) {
	if verboseLogging {
		log.Printf("webrtc: "+format, a...)
	}
}

// New constructs a Peer with sane defaults (STUN + TURN-fallback friendly).
func New() (*Peer, error) {
	cfg := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
		},
	}
	pc, err := webrtc.NewPeerConnection(cfg)
	if err != nil {
		return nil, err
	}
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		vlogf("ice state=%s", s.String())
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		vlogf("peer state=%s", s.String())
	})
	return &Peer{pc: pc, role: "daemon"}, nil
}

func (p *Peer) applyICEServers(servers []webrtc.ICEServer) error {
	if len(servers) == 0 {
		return nil
	}
	return p.pc.SetConfiguration(webrtc.Configuration{ICEServers: servers})
}

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
	servers := make([]webrtc.ICEServer, 0, len(out.IceServers))
	for _, s := range out.IceServers {
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
		servers = append(servers, webrtc.ICEServer{URLs: urls, Username: s.Username, Credential: s.Credential, CredentialType: webrtc.ICECredentialTypePassword})
	}
	return servers, nil
}

// NewDaemon creates offerer-side peer for valetfs serve.
func NewDaemon() (*Peer, error) { return New() }

// NewController creates answerer-side peer for valetfs vault pair.
func NewController() (*Peer, error) {
	p, err := New()
	if err != nil {
		return nil, err
	}
	p.role = "controller"
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
	return p, nil
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

// CreateOffer creates the "valetfs" DataChannel, generates an SDP offer and
// returns the local description encoded for transport to the signaling layer.
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
	<-webrtc.GatheringCompletePromise(p.pc)
	return *p.pc.LocalDescription(), nil
}

// AcceptAnswer applies the remote SDP answer.
func (p *Peer) AcceptAnswer(answer webrtc.SessionDescription) error {
	return p.pc.SetRemoteDescription(answer)
}

// AcceptOfferAndAnswer applies remote offer and returns local answer.
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
	<-webrtc.GatheringCompletePromise(p.pc)
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

// Bootstrap is the high-level helper used by production mode: it posts the
// offer to the Cloudflare Worker, prints an ASCII QR code containing the
// session id, then long-polls for the mobile app's answer.
func (p *Peer) Bootstrap(signalingURL string) error {
	if signalingURL == "" {
		return fmt.Errorf("webrtc: signaling URL is empty")
	}

	vlogf("bootstrap start signaling=%s", signalingURL)
	offer, err := p.CreateOffer()
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}

	signalingURL = strings.TrimRight(signalingURL, "/")
	payload, _ := json.Marshal(map[string]any{"role": "daemon", "offer": offer})
	resp, err := http.Post(signalingURL+"/sessions", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("post offer: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var created struct {
		SessionID string `json:"session_id"`
		Token     string `json:"daemon_token"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		return fmt.Errorf("decode session: %w", err)
	}
	if created.SessionID == "" {
		return fmt.Errorf("signaling did not return a session id")
	}
	vlogf("session created id=%s", created.SessionID)
	if iceServers, err := fetchICEServers(signalingURL, created.SessionID, created.Token); err == nil {
		if err := p.applyICEServers(iceServers); err == nil {
			vlogf("applied ice servers from signaling count=%d", len(iceServers))
		}
	} else {
		vlogf("turn fetch skipped: %v", err)
	}

	// Render QR code to terminal.
	qrterminal.GenerateHalfBlock(
		fmt.Sprintf("valetfs://pair?session=%s&url=%s", created.SessionID, signalingURL),
		qrterminal.L, os.Stdout)
	fmt.Printf("Session ID: %s\n", created.SessionID)
	fmt.Println("Scan with the ValetFS mobile app to pair.")

	// Long-poll the Worker for the remote answer.
	if err := p.startCandidateExchange(signalingURL, created.SessionID, created.Token, "daemon"); err != nil {
		return err
	}
	vlogf("candidate exchange started role=daemon")
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

// Join claims a daemon session as controller, exchanges SDP answer and connects.
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
	if iceServers, err := fetchICEServers(signalingURL, sessionID, claimed.ControllerToken); err == nil {
		if err := p.applyICEServers(iceServers); err == nil {
			vlogf("applied ice servers from signaling count=%d", len(iceServers))
		}
	} else {
		vlogf("turn fetch skipped: %v", err)
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

	deadline := time.Now().Add(30 * time.Second)
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
		vlogf("local candidate gathered role=%s", role)
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
				vlogf("remote candidate received role=%s", role)
				_ = p.AddRemoteCandidate(c)
			}
			since = out.Next
			time.Sleep(200 * time.Millisecond)
		}
	}()
	_ = role
	return nil
}
