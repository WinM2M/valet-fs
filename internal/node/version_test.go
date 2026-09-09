package node_test

import (
	"context"
	"testing"
	"time"

	"github.com/anomalyco/valet-fs/internal/rpc"
)

// The version list a client gets from the hub is unauthenticated: the hub could
// shrink it to push the session onto an older, weaker protocol. The daemon
// repeats it inside the encrypted channel so the two can be compared, and this
// checks the authenticated copy is really there and really matches.
func TestStatusReportsProtocolVersionsOverTheChannel(t *testing.T) {
	hubURL := newHub(t)
	h := startDaemon(t, hubURL, time.Minute)

	_, cl := connectVault(t, hubURL, h.sid)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := cl.Call(ctx, rpc.MethodStatus, nil)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	raw, ok := res.Result["protocol_versions"].([]any)
	if !ok {
		t.Fatal("STATUS must report protocol_versions over the encrypted channel")
	}
	got := make([]int, 0, len(raw))
	for _, v := range raw {
		got = append(got, int(v.(float64)))
	}
	if len(got) != len(rpc.Supported) {
		t.Fatalf("got %v, want %v", got, rpc.Supported)
	}
	for i := range got {
		if got[i] != rpc.Supported[i] {
			t.Fatalf("got %v, want %v", got, rpc.Supported)
		}
	}

	// A hub that shrank the list would disagree with this authenticated copy.
	if rpc.Negotiate([]int{}, 0) != 0 {
		t.Fatal("an empty offer must not negotiate")
	}
}
