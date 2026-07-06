//go:build linux

package vfs

import (
	"fmt"
	"os"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/winfsp/cgofuse/fuse"
)

// fuseMounter is the Linux (cgofuse) frontend for MemFS.
type fuseMounter struct {
	fuse.FileSystemBase
	mu   sync.Mutex
	fs   *MemFS
	host *fuse.FileSystemHost
}

func (f *fuseMounter) Mount(mountpoint string) error {
	if err := os.MkdirAll(mountpoint, 0o700); err != nil {
		return fmt.Errorf("mkdir mountpoint: %w", err)
	}
	PreUnmount(mountpoint)

	f.mu.Lock()
	f.host = fuse.NewFileSystemHost(f)
	f.host.SetCapReaddirPlus(true)
	f.mu.Unlock()

	opts := []string{"-o", "fsname=valetfs", "-o", "subtype=valetfs"}
	if !f.host.Mount(mountpoint, opts) {
		return fmt.Errorf("fuse mount failed at %s", mountpoint)
	}
	return nil
}

func (f *fuseMounter) Unmount() error {
	f.mu.Lock()
	host := f.host
	f.mu.Unlock()
	if host == nil {
		return nil
	}
	if !host.Unmount() {
		return fmt.Errorf("fuse unmount returned false")
	}
	return nil
}

func (*fuseMounter) Backend() string { return "fuse" }

// --- FUSE callbacks ---------------------------------------------------------

func (f *fuseMounter) Getattr(p string, stat *fuse.Stat_t, fh uint64) int {
	n, err := f.fs.Stat(p)
	if err != nil {
		return -fuse.ENOENT
	}
	fillStat(stat, n, f.fs, p)
	return 0
}

func (f *fuseMounter) Readdir(p string,
	fill func(name string, stat *fuse.Stat_t, ofst int64) bool,
	ofst int64, fh uint64) int {
	names, err := f.fs.List(p)
	if err != nil {
		return -fuse.ENOENT
	}
	fill(".", nil, 0)
	fill("..", nil, 0)
	for _, name := range names {
		var st fuse.Stat_t
		if n, err := f.fs.Stat(path.Join(p, name)); err == nil {
			fillStat(&st, n, f.fs, path.Join(p, name))
		}
		if !fill(name, &st, 0) {
			break
		}
	}
	return 0
}

func (f *fuseMounter) Open(p string, flags int) (int, uint64) {
	if _, err := f.fs.Stat(p); err != nil {
		return -fuse.ENOENT, 0
	}
	return 0, 0
}

func (f *fuseMounter) Read(p string, buff []byte, ofst int64, fh uint64) int {
	data, err := f.fs.Read(p)
	if err != nil {
		return -fuse.ENOENT
	}
	if ofst >= int64(len(data)) {
		return 0
	}
	n := copy(buff, data[ofst:])
	return n
}

func (f *fuseMounter) Write(p string, buff []byte, ofst int64, fh uint64) int {
	existing, err := f.fs.Read(p)
	if err != nil {
		existing = nil
	}
	end := ofst + int64(len(buff))
	if int64(len(existing)) < end {
		grown := make([]byte, end)
		copy(grown, existing)
		existing = grown
	}
	copy(existing[ofst:], buff)
	if err := f.fs.Write(p, existing, 0o600); err != nil {
		if err == ErrQuota {
			return -fuse.ENOSPC
		}
		return -fuse.EIO
	}
	return len(buff)
}

func (f *fuseMounter) Create(p string, flags int, mode uint32) (int, uint64) {
	if err := f.fs.Write(p, nil, 0o600); err != nil {
		if err == ErrExists {
			return 0, 0
		}
		return -fuse.EIO, 0
	}
	return 0, 0
}

func (f *fuseMounter) Truncate(p string, size int64, fh uint64) int {
	data, err := f.fs.Read(p)
	if err != nil {
		return -fuse.ENOENT
	}
	if int64(len(data)) > size {
		data = data[:size]
	} else if int64(len(data)) < size {
		grown := make([]byte, size)
		copy(grown, data)
		data = grown
	}
	if err := f.fs.Write(p, data, 0o600); err != nil {
		return -fuse.EIO
	}
	return 0
}

func (f *fuseMounter) Unlink(p string) int {
	if err := f.fs.Remove(p); err != nil {
		return -fuse.ENOENT
	}
	return 0
}

func (f *fuseMounter) Mkdir(p string, mode uint32) int {
	if err := f.fs.Mkdir(p, 0o755); err != nil {
		return -fuse.EIO
	}
	return 0
}

func (f *fuseMounter) Rmdir(p string) int {
	if err := f.fs.Remove(p); err != nil {
		return -fuse.EIO
	}
	return 0
}

func fillStat(st *fuse.Stat_t, n *Node, m *MemFS, p string) {
	now := fuse.NewTimespec(time.Now())
	mod := fuse.NewTimespec(n.ModTime)
	if n.IsDir {
		st.Mode = fuse.S_IFDIR | 0o755
		st.Nlink = 2
	} else {
		st.Mode = fuse.S_IFREG | 0o600
		st.Nlink = 1
		// Best-effort size lookup.
		if data, err := m.Read(p); err == nil {
			st.Size = int64(len(data))
		}
	}
	st.Atim = now
	st.Mtim = mod
	st.Ctim = mod
	st.Uid = uint32(syscall.Getuid())
	st.Gid = uint32(syscall.Getgid())
}
