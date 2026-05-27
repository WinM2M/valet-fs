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
		if flag&os.O_CREATE != 0 {
			if err := a.fs.Write(name, nil, perm); err != nil {
				return nil, err
			}
			n, _ = a.fs.Stat(name)
		} else {
			return nil, err
		}
	}
	if flag&os.O_TRUNC != 0 && n != nil && !n.IsDir {
		_ = a.fs.Write(name, nil, perm)
	}
	return &webdavFile{name: name, fs: a.fs}, nil
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
		return nil, err
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
}

func (f *webdavFile) Close() error { return nil }

func (f *webdavFile) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := f.fs.Read(f.name)
	if err != nil {
		return 0, err
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
		return nil, err
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
	if len(out) == 0 {
		return out, errors.New("eof")
	}
	return out, nil
}

func (f *webdavFile) Stat() (fs.FileInfo, error) {
	n, err := f.fs.Stat(f.name)
	if err != nil {
		return nil, err
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
