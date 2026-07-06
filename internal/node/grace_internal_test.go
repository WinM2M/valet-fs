package node

import (
	"testing"
	"time"

	"github.com/anomalyco/valet-fs/internal/vfs"
)

// A real RPC frame from the vault must cancel a pending grace even if the hub
// never delivered a peer_online presence frame. This is the reverse --join
// failure mode where an actively-connected app's just-pushed secret got wiped
// ~grace later purely because presence frames are a separate, flaky channel.
func TestInboundRPCCancelsGrace(t *testing.T) {
	fs := vfs.New(0)
	locked := make(chan struct{}, 1)
	n := New(Config{
		FS:      fs,
		Grace:   80 * time.Millisecond,
		Lock:    func() { locked <- struct{}{} },
		Mounted: func() bool { return true },
	})
	n.ArmGrace() // armed as in the reverse-join flow; no peer_online ever arrives

	time.Sleep(20 * time.Millisecond)
	// Inbound non-sys frame = a real vault RPC (here a STATUS request).
	n.onData([]byte(`{"v":1,"type":"REQ","id":"1","method":"STATUS"}`))

	select {
	case <-locked:
		t.Fatal("grace fired despite inbound vault RPC activity (should have been cancelled)")
	case <-time.After(160 * time.Millisecond):
		// grace was cancelled by the activity — correct.
	}
}

// Deny-by-default preserved: with no activity at all, ArmGrace still auto-locks.
func TestArmGraceLocksWithoutActivity(t *testing.T) {
	fs := vfs.New(0)
	locked := make(chan struct{}, 1)
	n := New(Config{
		FS:      fs,
		Grace:   40 * time.Millisecond,
		Lock:    func() { locked <- struct{}{} },
		Mounted: func() bool { return true },
	})
	n.ArmGrace()

	select {
	case <-locked:
		// locked as expected.
	case <-time.After(300 * time.Millisecond):
		t.Fatal("ArmGrace never locked despite no vault activity")
	}
}
