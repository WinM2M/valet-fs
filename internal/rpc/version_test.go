package rpc

import "testing"

func TestNegotiatePicksTheHighestShared(t *testing.T) {
	if got := Negotiate([]int{1}, 0); got != 1 {
		t.Fatalf("got %d, want 1", got)
	}
	// Versions this build does not know are ignored rather than accepted.
	if got := Negotiate([]int{1, 99}, 0); got != 1 {
		t.Fatalf("got %d, want 1", got)
	}
	if got := Negotiate([]int{99}, 0); got != 0 {
		t.Fatalf("no overlap must yield 0, got %d", got)
	}
	if got := Negotiate(nil, 0); got != 0 {
		t.Fatalf("no offer must yield 0, got %d", got)
	}
}

// A hub that reports a lower version than this client has already seen a daemon
// support is trying to walk it backwards onto the weaker protocol.
func TestNegotiateRefusesToGoBelowThePin(t *testing.T) {
	if got := Negotiate([]int{1}, 2); got != 0 {
		t.Fatalf("a downgrade below the pin must be refused, got %d", got)
	}
	if got := Negotiate([]int{1}, 1); got != 1 {
		t.Fatalf("meeting the pin exactly must be allowed, got %d", got)
	}
}
