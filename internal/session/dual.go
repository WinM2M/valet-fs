package session

import (
	"encoding/json"
	"sync"

	"github.com/anomalyco/valet-fs/internal/e2ee"
	"github.com/anomalyco/valet-fs/internal/transport"
)

// Dual lets one daemon connection serve both protocol versions, choosing by the
// shape of the first frame the peer sends rather than by anything negotiated
// beforehand.
//
// Choosing from the frame is deliberate. A negotiated choice has to travel
// through the hub before any channel exists, so the hub gets to influence it —
// that is what the version pin and the in-channel re-check exist to contain. The
// frame itself needs no such protection: a v1 hello cannot be mistaken for a v2
// handshake because they share no field, and neither can be forged into
// something it is not. The hub can drop frames, which it can always do; it
// cannot make a v2 vault look like a v1 one.
//
// Serving v1 at all is temporary. It is what keeps the App Store build working
// while v2 rolls out, and M3 removes it.
type Dual struct {
	inner transport.Conn
	// shim sits between the chosen layer and the real transport so this
	// dispatcher keeps the read path. Both layers call OnData on whatever they
	// are given, which would otherwise replace the dispatcher's own handler and
	// lose the very frame that selected the version.
	shim *shimConn

	mu       sync.Mutex
	v1cfg    *e2ee.KeyPair
	v2cfg    Config
	chosen   transport.Conn
	version  int
	onData   func([]byte)
	onOpen   func()
	onClose  func()
	onChoose func(version int)
}

// shimConn forwards sends to the real transport and receives frames only when
// Dual hands them over.
type shimConn struct {
	inner transport.Conn

	mu     sync.Mutex
	onData func([]byte)
}

func (s *shimConn) OnData(fn func([]byte)) { s.mu.Lock(); s.onData = fn; s.mu.Unlock() }
func (s *shimConn) OnOpen(func())          {}
func (s *shimConn) OnClose(fn func())      { s.inner.OnClose(fn) }
func (s *shimConn) Send(b []byte) error    { return s.inner.Send(b) }
func (s *shimConn) Close() error           { return s.inner.Close() }
func (s *shimConn) feed(b []byte) {
	s.mu.Lock()
	fn := s.onData
	s.mu.Unlock()
	if fn != nil {
		fn(b)
	}
}

// DualConfig wires both protocol paths. Whichever the peer opens with wins.
type DualConfig struct {
	Inner transport.Conn
	// V1Static is the X25519 key pair the v1 layer uses.
	V1Static *e2ee.KeyPair
	// V2 configures the Noise layer. Inner is filled in from Inner above.
	V2 Config
	// OnChoose reports which version the peer selected, so the daemon can log it
	// and a later milestone can warn about v1.
	OnChoose func(version int)
}

// NewDual returns a connection that has not yet chosen a version.
func NewDual(cfg DualConfig) *Dual {
	d := &Dual{
		inner: cfg.Inner, shim: &shimConn{inner: cfg.Inner},
		v1cfg: cfg.V1Static, v2cfg: cfg.V2, onChoose: cfg.OnChoose,
	}
	d.v2cfg.Inner = d.shim
	cfg.Inner.OnData(d.handle)
	return d
}

type probe struct {
	Sys string `json:"sys,omitempty"`
	KX  string `json:"kx,omitempty"`
	NX  string `json:"nx,omitempty"`
}

func (d *Dual) handle(b []byte) {
	var p probe
	if json.Unmarshal(b, &p) != nil {
		return
	}

	d.mu.Lock()
	chosen := d.chosen
	d.mu.Unlock()

	if chosen == nil {
		switch {
		case p.NX == "1":
			d.choose(2)
		case p.KX == "hello":
			d.choose(1)
		case p.Sys != "":
			// Presence can arrive before either handshake. Pass it straight
			// through: the node needs peer_offline to arm grace whether or not a
			// version has been settled.
			d.deliver(b)
			return
		default:
			return // not a frame either layer understands
		}
	}
	// Every frame, including the one that chose the version, reaches the layer
	// through the shim. Nothing is dropped on the transition.
	d.shim.feed(b)
}

func (d *Dual) choose(version int) {
	d.mu.Lock()
	if d.chosen != nil {
		d.mu.Unlock()
		return
	}
	var picked transport.Conn
	switch version {
	case 2:
		c, err := NewDaemon(d.v2cfg)
		if err != nil {
			d.mu.Unlock()
			return
		}
		c.OnData(d.deliver)
		picked = c
	case 1:
		c := e2ee.WrapDaemon(d.shim, d.v1cfg)
		c.OnData(d.deliver)
		picked = c
	}
	d.chosen = picked
	d.version = version
	onChoose := d.onChoose
	d.mu.Unlock()

	if onChoose != nil {
		onChoose(version)
	}
}

func (d *Dual) deliver(b []byte) {
	d.mu.Lock()
	fn := d.onData
	d.mu.Unlock()
	if fn != nil {
		fn(b)
	}
}

// Version reports the chosen protocol version, or 0 before the peer has spoken.
func (d *Dual) Version() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.version
}

// Send routes to whichever layer was chosen. Before that there is nothing to
// send on, which is correct: the daemon never speaks first.
func (d *Dual) Send(b []byte) error {
	d.mu.Lock()
	chosen := d.chosen
	d.mu.Unlock()
	if chosen == nil {
		return ErrNotEstablished
	}
	return chosen.Send(b)
}

func (d *Dual) OnData(fn func([]byte)) { d.mu.Lock(); d.onData = fn; d.mu.Unlock() }
func (d *Dual) OnOpen(fn func())       { d.mu.Lock(); d.onOpen = fn; d.mu.Unlock() }
func (d *Dual) OnClose(fn func())      { d.mu.Lock(); d.onClose = fn; d.mu.Unlock(); d.inner.OnClose(fn) }
func (d *Dual) Close() error           { return d.inner.Close() }

// Start starts the underlying transport. Neither layer sends anything from the
// daemon side until the peer opens.
func (d *Dual) Start() {
	if s, ok := d.inner.(interface{ Start() }); ok {
		s.Start()
	}
	d.mu.Lock()
	fn := d.onOpen
	d.mu.Unlock()
	if fn != nil {
		fn()
	}
}
