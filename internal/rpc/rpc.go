// Package rpc defines the transport-neutral request/response protocol spoken
// between a vault controller and a daemon over any transport.Conn.
//
// A frame is a JSON-encoded Message. Requests carry a Method + Params and a
// unique ID; responses echo that ID with OK/Result/Err. The format is kept
// intentionally close to the legacy webrtc RPCMessage so handlers are easy to
// port.
package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/anomalyco/valet-fs/internal/transport"
	"github.com/google/uuid"
)

// Message types.
const (
	TypeReq = "REQ"
	TypeRes = "RES"
)

// Methods understood by the daemon dispatcher.
const (
	MethodWrite     = "WRITE"
	MethodDelete    = "DELETE"
	MethodUnmount   = "UNMOUNT"
	MethodLock      = "LOCK"
	MethodStatus    = "STATUS"
	MethodManifest  = "MANIFEST"
	MethodPull      = "PULL"
	MethodSetConfig = "SET_CONFIG"
)

// Message is a single RPC frame.
type Message struct {
	V      int            `json:"v"`
	ID     string         `json:"id,omitempty"`
	Type   string         `json:"type"`
	Method string         `json:"method,omitempty"`
	Params map[string]any `json:"params,omitempty"`
	OK     bool           `json:"ok,omitempty"`
	Result map[string]any `json:"result,omitempty"`
	Err    string         `json:"error,omitempty"`
}

// NewRequest builds a REQ frame with a fresh ID.
func NewRequest(method string, params map[string]any) Message {
	return Message{V: 1, ID: uuid.NewString(), Type: TypeReq, Method: method, Params: params}
}

// Reply builds a RES frame correlated to req.
func Reply(req Message, ok bool, result map[string]any, err error) Message {
	m := Message{V: 1, ID: req.ID, Type: TypeRes, OK: ok, Result: result}
	if err != nil {
		m.Err = err.Error()
	}
	return m
}

// Encode marshals a Message to JSON bytes.
func Encode(m Message) []byte {
	b, _ := json.Marshal(m)
	return b
}

// Decode unmarshals a JSON frame.
func Decode(b []byte) (Message, error) {
	var m Message
	err := json.Unmarshal(b, &m)
	return m, err
}

// Handler processes a single request and returns a result map or an error.
type Handler func(req Message) (map[string]any, error)

// Dispatcher routes inbound requests to registered handlers.
type Dispatcher struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// NewDispatcher returns an empty dispatcher.
func NewDispatcher() *Dispatcher { return &Dispatcher{handlers: map[string]Handler{}} }

// Handle registers a handler for a method (case-insensitive).
func (d *Dispatcher) Handle(method string, h Handler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[strings.ToUpper(method)] = h
}

// Dispatch decodes a frame; if it is a request, it runs the handler and returns
// the reply frame to send back. isReq reports whether the frame was a request
// (non-requests such as responses are ignored and yield isReq=false).
func (d *Dispatcher) Dispatch(raw []byte) (reply []byte, isReq bool) {
	m, err := Decode(raw)
	if err != nil || m.Type != TypeReq {
		return nil, false
	}
	d.mu.RLock()
	h, ok := d.handlers[strings.ToUpper(m.Method)]
	d.mu.RUnlock()
	if !ok {
		return Encode(Reply(m, false, nil, fmt.Errorf("unknown method %q", m.Method))), true
	}
	res, herr := h(m)
	return Encode(Reply(m, herr == nil, res, herr)), true
}

// Client issues requests over a transport.Conn and correlates responses by ID.
// It installs itself as the connection's OnData handler, ignoring any frame that
// is not a RES (e.g. presence/system frames).
type Client struct {
	conn    transport.Conn
	mu      sync.Mutex
	pending map[string]chan Message
}

// NewClient wires a Client onto conn. Do not also set conn.OnData elsewhere.
func NewClient(conn transport.Conn) *Client {
	c := &Client{conn: conn, pending: map[string]chan Message{}}
	conn.OnData(c.onData)
	return c
}

func (c *Client) onData(b []byte) {
	m, err := Decode(b)
	if err != nil || m.Type != TypeRes {
		return
	}
	c.mu.Lock()
	ch := c.pending[m.ID]
	delete(c.pending, m.ID)
	c.mu.Unlock()
	if ch != nil {
		ch <- m
	}
}

// Call sends a request and waits for the correlated response or ctx cancel.
func (c *Client) Call(ctx context.Context, method string, params map[string]any) (Message, error) {
	req := NewRequest(method, params)
	ch := make(chan Message, 1)
	c.mu.Lock()
	c.pending[req.ID] = ch
	c.mu.Unlock()
	if err := c.conn.Send(Encode(req)); err != nil {
		c.mu.Lock()
		delete(c.pending, req.ID)
		c.mu.Unlock()
		return Message{}, err
	}
	select {
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, req.ID)
		c.mu.Unlock()
		return Message{}, ctx.Err()
	case m := <-ch:
		if !m.OK {
			return m, fmt.Errorf("rpc %s failed: %s", method, m.Err)
		}
		return m, nil
	}
}
