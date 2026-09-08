//go:build !linux

package hardening

// Apply is a no-op outside Linux. The equivalents exist elsewhere (mlock on
// BSD, VirtualLock on Windows) but are not wired up, so the report says so
// rather than implying a protection that is not there.
func Apply() Report {
	return Report{Notes: []string{
		"memory locking and core dump suppression are only implemented on Linux; " +
			"secrets in this process may reach swap or a core dump",
	}}
}
