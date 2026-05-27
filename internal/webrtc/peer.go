// Package webrtc wraps pion/webrtc to expose ValetFS' P2P data channel and
// handles QR-code-based session bootstrap against a Cloudflare Worker.
package webrtc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	onData  func([]byte)
	onOpen  func()
	onClose func()
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
	return &Peer{pc: pc}, nil
}

// OnData registers a callback invoked for each inbound DataChannel message.
func (p *Peer) OnData(fn func([]byte)) { p.onData = fn }

// OnOpen registers a callback invoked once the DataChannel transitions to open.
func (p *Peer) OnOpen(fn func()) { p.onOpen = fn }

// OnClose registers a callback invoked when the DataChannel is closed.
func (p *Peer) OnClose(fn func()) { p.onClose = fn }

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

	offer, err := p.CreateOffer()
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}

	payload, _ := json.Marshal(map[string]any{"offer": offer})
	resp, err := http.Post(signalingURL+"/sessions", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("post offer: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var created struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		return fmt.Errorf("decode session: %w", err)
	}
	if created.SessionID == "" {
		return fmt.Errorf("signaling did not return a session id")
	}

	// Render QR code to terminal.
	qrterminal.GenerateHalfBlock(
		fmt.Sprintf("valetfs://pair?session=%s&url=%s", created.SessionID, signalingURL),
		qrterminal.L, os.Stdout)
	fmt.Println("Scan with the ValetFS mobile app to pair.")

	// Long-poll the Worker for the remote answer.
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		ar, err := http.Get(signalingURL + "/sessions/" + created.SessionID + "/answer")
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		ab, _ := io.ReadAll(ar.Body)
		ar.Body.Close()
		if ar.StatusCode == http.StatusOK && len(ab) > 0 {
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
