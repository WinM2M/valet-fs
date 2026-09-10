// Package hardening applies the process-level protections a daemon holding
// plaintext secrets in memory needs, but which Go does not do by default.
//
// MemFS.Wipe zeroes the heap when the daemon locks. That protects the secrets
// once they are meant to be gone; it does nothing while they are live. A
// running daemon's memory is readable by anything with the same uid through
// /proc/<pid>/mem or ptrace, it lands in a core dump if the process crashes,
// and the kernel is free to write it to swap where it outlives the process
// entirely. Those three holes are what this package closes.
package hardening

// Report describes what was applied and what was not, so the caller can say so
// out loud rather than pretending the process is protected when it is not.
type Report struct {
	// MemoryLocked means pages will not be written to swap.
	MemoryLocked bool
	// DumpsDisabled means core dumps and same-uid ptrace are refused.
	DumpsDisabled bool
	// Notes explains anything that could not be applied.
	Notes []string
}
