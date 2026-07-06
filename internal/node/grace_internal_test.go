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

// A WRITE after a LOCK (unmount + wipe) must auto-remount so the re-pushed
// secret is served again instead of being orphaned in an unmounted heap.
func TestWriteRemountsAfterLock(t *testing.T) {
	fs := vfs.New(0)
	mounted := true
	n := New(Config{
		FS:      fs,
		Mounted: func() bool { return mounted },
		Lock:    func() { mounted = false; fs.Wipe() },
		Remount: func() { mounted = true },
	})

	n.onData([]byte(`{"v":1,"type":"REQ","id":"1","method":"LOCK"}`))
	if mounted {
		t.Fatal("expected unmounted after LOCK")
	}
	n.onData([]byte(`{"v":1,"type":"REQ","id":"2","method":"WRITE","params":{"path":"/keys/x","content":"hi"}}`))
	if !mounted {
		t.Fatal("expected auto-remount after WRITE following a LOCK")
	}
	if fs.Used() == 0 {
		t.Fatal("expected the re-pushed file to be written")
	}
}

// UNMOUNT preserves the heap (stops serving only); LOCK wipes it.
func TestUnmountKeepsHeapLockWipes(t *testing.T) {
	fs := vfs.New(0)
	_ = fs.MkdirAll("/keys", 0o755)
	_ = fs.Write("/keys/x", []byte("secret"), 0o600)
	unmounted, wiped := 0, 0
	n := New(Config{
		FS:      fs,
		Mounted: func() bool { return true },
		Lock:    func() { wiped++; fs.Wipe() },
		Unmount: func() { unmounted++ },
	})

	n.onData([]byte(`{"v":1,"type":"REQ","id":"1","method":"UNMOUNT"}`))
	if unmounted != 1 || wiped != 0 {
		t.Fatalf("UNMOUNT should call Unmount only (unmounted=%d wiped=%d)", unmounted, wiped)
	}
	if fs.Used() == 0 {
		t.Fatal("UNMOUNT wiped the heap (should preserve it)")
	}

	n.onData([]byte(`{"v":1,"type":"REQ","id":"2","method":"LOCK"}`))
	if wiped != 1 {
		t.Fatal("LOCK should wipe the heap")
	}
	if fs.Used() != 0 {
		t.Fatal("LOCK did not wipe the heap")
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
