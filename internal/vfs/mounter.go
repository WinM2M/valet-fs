package vfs

// Mounter is the platform-specific frontend that exposes a MemFS to the OS.
type Mounter interface {
	// Mount blocks until the FS is unmounted. It must be safe to call exactly once.
	Mount(mountpoint string) error
	// Unmount triggers a graceful unmount and causes Mount to return.
	Unmount() error
	// Backend reports the frontend actually in use so callers (and STATUS
	// clients) can distinguish a real kernel mount from the loopback WebDAV
	// fallback: "fuse" (kernel-backed), "webdav" (loopback HTTP), or "none"
	// (unsupported platform).
	Backend() string
}
