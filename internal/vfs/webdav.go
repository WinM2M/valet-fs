package vfs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"sync"
	"time"

	"golang.org/x/net/webdav"
)

// webdavAdapter exposes a MemFS through the webdav.FileSystem interface.
type webdavAdapter struct{ fs *MemFS }

func newWebdavAdapter(m *MemFS) webdav.FileSystem { return &webdavAdapter{fs: m} }

func (a *webdavAdapter) Mkdir(_ context.Context, name string, perm os.FileMode) error {
	return a.fs.Mkdir(name, perm)
}

func (a *webdavAdapter) OpenFile(_ context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	n, err := a.fs.Stat(name)
	if err != nil {
		if flag&os.O_CREATE == 0 {
			return nil, mapErr(err)
		}
		// Auto-create any missing parent dirs so PUT /a/b/c.txt works
		// without requiring an explicit MKCOL chain first. WebDAV
		// clients (curl, Finder, davfs2) all assume this works.
		if dir := path.Dir(name); dir != "" && dir != "." && dir != "/" {
			_ = a.fs.MkdirAll(dir, 0o700)
		}
		if err := a.fs.Write(name, nil, perm); err != nil {
			return nil, mapErr(err)
		}
		n, _ = a.fs.Stat(name)
	}
	if flag&os.O_TRUNC != 0 && n != nil && !n.IsDir {
		if err := a.fs.Write(name, nil, perm); err != nil {
			return nil, mapErr(err)
		}
	}
	return &webdavFile{name: name, fs: a.fs, isDir: n != nil && n.IsDir}, nil
}

// mapErr converts MemFS sentinels into errors the net/webdav handler knows
// how to translate into proper HTTP status codes. Returning a bare error
// causes the handler to surface 500 Internal Server Error instead of 404.
func mapErr(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return os.ErrNotExist
	case errors.Is(err, ErrExists):
		return os.ErrExist
	case errors.Is(err, ErrInvalidPath):
		return os.ErrInvalid
	default:
		return err
	}
}

func (a *webdavAdapter) RemoveAll(_ context.Context, name string) error {
	return a.fs.Remove(name)
}

func (a *webdavAdapter) Rename(_ context.Context, oldName, newName string) error {
	data, err := a.fs.Read(oldName)
	if err != nil {
		return err
	}
	if err := a.fs.Write(newName, data, 0o600); err != nil {
		return err
	}
	return a.fs.Remove(oldName)
}

func (a *webdavAdapter) Stat(_ context.Context, name string) (fs.FileInfo, error) {
	n, err := a.fs.Stat(name)
	if err != nil {
		return nil, mapErr(err)
	}
	size := int64(0)
	if !n.IsDir {
		if data, err := a.fs.Read(name); err == nil {
			size = int64(len(data))
		}
	}
	return &nodeInfo{node: n, size: size}, nil
}

type webdavFile struct {
	mu     sync.Mutex
	name   string
	fs     *MemFS
	offset int64
	isDir  bool
}

func (f *webdavFile) Close() error { return nil }

func (f *webdavFile) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.isDir {
		return 0, errors.New("is a directory")
	}
	data, err := f.fs.Read(f.name)
	if err != nil {
		return 0, mapErr(err)
	}
	if f.offset >= int64(len(data)) {
		return 0, io.EOF
	}
	n := copy(p, data[f.offset:])
	f.offset += int64(n)
	return n, nil
}

func (f *webdavFile) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, _ := f.fs.Read(f.name)
	switch whence {
	case io.SeekStart:
		f.offset = offset
	case io.SeekCurrent:
		f.offset += offset
	case io.SeekEnd:
		f.offset = int64(len(data)) + offset
	}
	return f.offset, nil
}

func (f *webdavFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, _ := f.fs.Read(f.name)
	end := f.offset + int64(len(p))
	if int64(len(data)) < end {
		grown := make([]byte, end)
		copy(grown, data)
		data = grown
	}
	copy(data[f.offset:], p)
	if err := f.fs.Write(f.name, data, 0o600); err != nil {
		return 0, err
	}
	f.offset += int64(len(p))
	return len(p), nil
}

func (f *webdavFile) Readdir(count int) ([]fs.FileInfo, error) {
	names, err := f.fs.List(f.name)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]fs.FileInfo, 0, len(names))
	for _, name := range names {
		full := path.Join(f.name, name)
		n, err := f.fs.Stat(full)
		if err != nil {
			continue
		}
		size := int64(0)
		if !n.IsDir {
			if data, err := f.fs.Read(full); err == nil {
				size = int64(len(data))
			}
		}
		out = append(out, &nodeInfo{node: n, size: size})
	}
	if count > 0 && count < len(out) {
		out = out[:count]
	}
	// IMPORTANT: an empty directory must return (empty slice, nil) — NOT
	// a bespoke error. The net/webdav handler treats any non-nil error
	// other than io.EOF as a server fault and aborts the PROPFIND with
	// 500 mid-response. Returning io.EOF is also accepted when count > 0.
	return out, nil
}

func (f *webdavFile) Stat() (fs.FileInfo, error) {
	n, err := f.fs.Stat(f.name)
	if err != nil {
		return nil, mapErr(err)
	}
	size := int64(0)
	if !n.IsDir {
		if data, err := f.fs.Read(f.name); err == nil {
			size = int64(len(data))
		}
	}
	return &nodeInfo{node: n, size: size}, nil
}

type nodeInfo struct {
	node *Node
	size int64
}

func (n *nodeInfo) Name() string       { return n.node.Name }
func (n *nodeInfo) Size() int64        { return n.size }
func (n *nodeInfo) Mode() os.FileMode  { return n.node.Mode }
func (n *nodeInfo) ModTime() time.Time { return n.node.ModTime }
func (n *nodeInfo) IsDir() bool        { return n.node.IsDir }
func (n *nodeInfo) Sys() interface{}   { return nil }
