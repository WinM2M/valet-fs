//go:build linux

package hardening

import (
	"testing"

	"golang.org/x/sys/unix"
)

// Apply must actually change the process, not merely report that it did. A
// dumpable process can be attached to by anything running as the same user,
// which reads the plaintext secrets straight out of the heap.
func TestApplyDisablesDumpsForReal(t *testing.T) {
	r := Apply()
	if !r.DumpsDisabled {
		t.Fatalf("dumps not disabled: %v", r.Notes)
	}
	got, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("PR_GET_DUMPABLE: %v", err)
	}
	if got != 0 {
		t.Fatalf("process is still dumpable (PR_GET_DUMPABLE=%d)", got)
	}

	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	if lim.Cur != 0 {
		t.Fatalf("core dump limit is %d, want 0", lim.Cur)
	}
}

// A tight RLIMIT_MEMLOCK must be reported, not silently ignored, and not turned
// into failing heap allocations by locking anyway.
func TestMemlockHeadroomMatchesTheActualLimit(t *testing.T) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		t.Skip("cannot read RLIMIT_MEMLOCK")
	}
	ok, why := memlockHeadroom()
	generous := lim.Cur == unix.RLIM_INFINITY || lim.Cur >= 512<<20
	if ok != generous {
		t.Fatalf("headroom=%v for limit %d (want %v)", ok, lim.Cur, generous)
	}
	if !ok && why == "" {
		t.Fatal("skipping the lock must come with an explanation")
	}
}
