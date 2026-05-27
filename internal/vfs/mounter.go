package vfs

// Mounter is the platform-specific frontend that exposes a MemFS to the OS.
type Mounter interface {
	// Mount blocks until the FS is unmounted. It must be safe to call exactly once.
	Mount(mountpoint string) error
	// Unmount triggers a graceful unmount and causes Mount to return.
	Unmount() error
}
