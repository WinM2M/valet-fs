//go:build linux

package hardening

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Apply locks the process's memory and disables core dumps.
//
// None of this is fatal if it fails. A daemon that cannot lock its memory is
// still far more useful than one that refuses to start, and the caller reports
// what was skipped so the weaker guarantee is visible instead of assumed.
//
// Note on scope: PR_SET_DUMPABLE stops a same-uid process from attaching and
// stops core dumps. It does not stop root. Nothing in userspace can.
func Apply() Report {
	var r Report

	// MCL_FUTURE matters as much as MCL_CURRENT: secrets arrive after startup,
	// into memory allocated later. But it also means every future allocation
	// must fit under RLIMIT_MEMLOCK, and a Go heap that grows past a modest
	// limit starts failing to allocate — turning a hardening measure into a
	// crash. Only lock when the limit is generous enough to be safe.
	if ok, why := memlockHeadroom(); !ok {
		r.Notes = append(r.Notes, why+"; secrets may be written to swap")
	} else if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"could not lock memory (%v); secrets may be written to swap - raise RLIMIT_MEMLOCK "+
				"(ulimit -l) or grant CAP_IPC_LOCK", err))
	} else {
		r.MemoryLocked = true
	}

	// Two separate mechanisms: the rlimit bounds a dump's size, PR_SET_DUMPABLE
	// stops it being produced at all and also blocks same-uid ptrace.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		r.Notes = append(r.Notes, fmt.Sprintf("could not zero the core dump limit (%v)", err))
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"could not disable core dumps and ptrace (%v); another process running as this "+
				"user could read the secrets out of memory", err))
	} else {
		r.DumpsDisabled = true
	}

	return r
}

// memlockHeadroom reports whether RLIMIT_MEMLOCK is roomy enough that locking
// all future allocations will not starve the heap.
func memlockHeadroom() (bool, string) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		return false, fmt.Sprintf("could not read RLIMIT_MEMLOCK (%v), so memory was not locked", err)
	}
	if lim.Cur == unix.RLIM_INFINITY {
		return true, ""
	}
	const minimum = 512 << 20
	if lim.Cur < minimum {
		return false, fmt.Sprintf(
			"RLIMIT_MEMLOCK is %d MiB, too low to lock the heap safely, so memory was not locked "+
				"(raise it with ulimit -l or grant CAP_IPC_LOCK)", lim.Cur>>20)
	}
	return true, ""
}
