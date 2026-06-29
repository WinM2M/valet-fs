// Package transport defines the minimal duplex message channel used between a
// ValetFS daemon and a vault controller. Both the legacy WebRTC DataChannel and
// the new WebSocket/Durable-Object hub satisfy this interface, so the rest of
// the system is transport-agnostic.
package transport

// Conn is a bidirectional, message-oriented connection. Implementations deliver
// whole frames (not byte streams) to the OnData callback.
type Conn interface {
	// OnData registers the callback invoked for each inbound frame.
	OnData(func([]byte))
	// OnOpen registers a callback invoked once the connection is usable.
	OnOpen(func())
	// OnClose registers a callback invoked once the connection is torn down.
	OnClose(func())
	// Send transmits a single frame to the peer.
	Send([]byte) error
	// Close tears the connection down.
	Close() error
}
