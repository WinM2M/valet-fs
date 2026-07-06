//go:build linux

package vfs

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"
)

// fuseAvailability is the result of a self-diagnosis for whether the running
// process can mount a FUSE filesystem.
type fuseAvailability struct {
	OK     bool
	Reason string
}

// checkFUSE inspects the environment for the prerequisites of a kernel FUSE
// mount: the /dev/fuse character device must exist and be readable+writable
// by the current process. fusermount must also be on PATH (cgofuse shells
// out to it for unmount). It does NOT try to load the kernel module here.
func checkFUSE() fuseAvailability {
	fi, err := os.Stat("/dev/fuse")
	if err != nil {
		return fuseAvailability{Reason: fmt.Sprintf("/dev/fuse not present (%v)", err)}
	}
	if fi.Mode()&os.ModeCharDevice == 0 {
		return fuseAvailability{Reason: "/dev/fuse exists but is not a character device"}
	}
	f, err := os.OpenFile("/dev/fuse", os.O_RDWR, 0)
	if err != nil {
		return fuseAvailability{Reason: fmt.Sprintf("/dev/fuse not openable: %v", err)}
	}
	_ = f.Close()
	if _, err := exec.LookPath("fusermount"); err != nil {
		if _, err2 := exec.LookPath("fusermount3"); err2 != nil {
			return fuseAvailability{Reason: "neither fusermount nor fusermount3 found on PATH"}
		}
	}
	return fuseAvailability{OK: true}
}

// tryEnableFUSE attempts to make FUSE usable without any user interaction.
// It tries `modprobe fuse` first directly (works if we are root, which the
// daemon often is when launched as a system service) and then `sudo -n` as a
// passwordless fallback. Any failure is silent; the caller will fall back to
// the WebDAV mounter.
func tryEnableFUSE() {
	cmds := [][]string{
		{"modprobe", "fuse"},
		{"sudo", "-n", "modprobe", "fuse"},
	}
	for _, c := range cmds {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		cmd := exec.Command(c[0], c[1:]...)
		if err := cmd.Run(); err == nil {
			return
		}
	}
}

// NewMounter picks the best available frontend for the current host. It
// prefers a real FUSE mount (transparent to the user's tools) but seamlessly
// falls back to an in-process WebDAV server when FUSE is unavailable, so the
// user never has to run modprobe, install drivers, or escalate privileges.
func NewMounter(m *MemFS) Mounter {
	avail := checkFUSE()
	if !avail.OK {
		// Attempt one self-healing pass before giving up.
		tryEnableFUSE()
		avail = checkFUSE()
	}
	if avail.OK {
		return &fuseMounter{fs: m}
	}
	log.Printf("valetfs: FUSE unavailable (%s); falling back to loopback WebDAV", avail.Reason)
	log.Printf("valetfs: agents and `curl` can access files at http://<webdav-addr>/")
	return &fallbackMounter{inner: NewWebdavMounter(m, "127.0.0.1:0")}
}

// PreUnmount forcefully detaches any ghost FUSE mount left over from a
// previous run. Safe to call even when FUSE is not available.
func PreUnmount(mountpoint string) {
	if _, err := os.Stat(mountpoint); err != nil {
		return
	}
	_ = exec.Command("fusermount", "-uz", mountpoint).Run()
}

// fallbackMounter wraps a WebdavMounter and prints its bound address once
// the listener is up, so the user immediately knows where to reach the VFS.
type fallbackMounter struct {
	inner *WebdavMounter
}

func (f *fallbackMounter) Mount(mountpoint string) error {
	// Spin a poller that prints the resolved port once Serve() has bound.
	stop := make(chan struct{})
	go func() {
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-deadline.C:
				return
			case <-tick.C:
				addr := f.inner.Addr()
				if addr != "" && addr != "127.0.0.1:0" {
					log.Printf("valetfs: WebDAV fallback ready at http://%s/  (mountpoint hint: %s)", addr, mountpoint)
					return
				}
			}
		}
	}()
	err := f.inner.Mount(mountpoint)
	close(stop)
	return err
}

func (f *fallbackMounter) Unmount() error { return f.inner.Unmount() }

func (*fallbackMounter) Backend() string { return "webdav" }
