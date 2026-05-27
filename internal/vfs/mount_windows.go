//go:build windows

package vfs

import (
	"fmt"
	"log"
	"os/exec"
)

// NewMounter on Windows returns a WebDAV mounter and best-effort maps it as a
// drive letter so the user does not have to run "net use" manually.
func NewMounter(m *MemFS) Mounter {
	return &windowsMounter{inner: NewWebdavMounter(m, "127.0.0.1:8088")}
}

// PreUnmount removes any stale network mapping left from a previous run.
func PreUnmount(mountpoint string) {
	_ = exec.Command("net", "use", mountpoint, "/delete", "/y").Run()
}

type windowsMounter struct {
	inner *WebdavMounter
	point string
}

func (w *windowsMounter) Mount(mountpoint string) error {
	PreUnmount(mountpoint)
	w.point = mountpoint

	// Best-effort drive-letter mapping (e.g. "Z:").
	if len(mountpoint) >= 2 && mountpoint[1] == ':' {
		go func() {
			url := fmt.Sprintf("http://%s/", w.inner.Addr())
			if err := exec.Command("net", "use", mountpoint, url).Run(); err != nil {
				log.Printf("valetfs: net use mapping failed: %v (access via %s)", err, url)
			}
		}()
	}
	return w.inner.Mount(mountpoint)
}

func (w *windowsMounter) Unmount() error {
	if w.point != "" {
		PreUnmount(w.point)
	}
	return w.inner.Unmount()
}
