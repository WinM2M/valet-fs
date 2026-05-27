// Package vfs implements the in-memory file system backing ValetFS.
//
// The core MemFS type is OS-agnostic and exposes a minimal POSIX-like API,
// allowing platform-specific frontends (FUSE on Linux, WebDAV on Windows)
// to share a single canonical implementation.
//
// SECURITY: all file bodies live exclusively on the heap. The Wipe method
// zero-fills every byte slice before drop so that token material does not
// linger in the heap after shutdown.
package vfs

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// Common errors returned by MemFS.
var (
	ErrNotFound    = errors.New("valetfs: not found")
	ErrExists      = errors.New("valetfs: already exists")
	ErrNotDir      = errors.New("valetfs: not a directory")
	ErrIsDir       = errors.New("valetfs: is a directory")
	ErrQuota       = errors.New("valetfs: quota exceeded")
	ErrInvalidPath = errors.New("valetfs: invalid path")
)

// Node represents a single inode within the in-memory tree.
type Node struct {
	Name     string
	IsDir    bool
	Mode     fs.FileMode
	ModTime  time.Time
	Data     []byte           // for files only
	Children map[string]*Node // for dirs only
}

// MemFS is a tiny thread-safe in-memory file system.
type MemFS struct {
	mu    sync.RWMutex
	root  *Node
	used  int64
	quota int64
}

// New returns an empty MemFS with the given quota in bytes (0 = unlimited).
func New(quotaBytes int64) *MemFS {
	return &MemFS{
		root: &Node{
			Name:     "/",
			IsDir:    true,
			Mode:     0o755 | fs.ModeDir,
			ModTime:  time.Now(),
			Children: make(map[string]*Node),
		},
		quota: quotaBytes,
	}
}

// Used returns the current heap byte usage.
func (m *MemFS) Used() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.used
}

// normalize cleans a path and rejects traversal attempts.
func normalize(p string) ([]string, error) {
	if p == "" {
		return nil, ErrInvalidPath
	}
	p = path.Clean("/" + p)
	if p == "/" {
		return []string{}, nil
	}
	if strings.Contains(p, "..") {
		return nil, ErrInvalidPath
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	return parts, nil
}

func (m *MemFS) walk(parts []string) (*Node, error) {
	n := m.root
	for _, part := range parts {
		if !n.IsDir {
			return nil, ErrNotDir
		}
		child, ok := n.Children[part]
		if !ok {
			return nil, ErrNotFound
		}
		n = child
	}
	return n, nil
}

func (m *MemFS) walkParent(parts []string) (*Node, string, error) {
	if len(parts) == 0 {
		return nil, "", ErrInvalidPath
	}
	parent, err := m.walk(parts[:len(parts)-1])
	if err != nil {
		return nil, "", err
	}
	if !parent.IsDir {
		return nil, "", ErrNotDir
	}
	return parent, parts[len(parts)-1], nil
}

// Mkdir creates a directory. Parents must already exist.
func (m *MemFS) Mkdir(p string, mode fs.FileMode) error {
	parts, err := normalize(p)
	if err != nil {
		return err
	}
	if len(parts) == 0 {
		return ErrExists
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	parent, name, err := m.walkParent(parts)
	if err != nil {
		return err
	}
	if _, ok := parent.Children[name]; ok {
		return ErrExists
	}
	parent.Children[name] = &Node{
		Name:     name,
		IsDir:    true,
		Mode:     mode | fs.ModeDir,
		ModTime:  time.Now(),
		Children: make(map[string]*Node),
	}
	parent.ModTime = time.Now()
	return nil
}

// MkdirAll creates a directory chain, similar to os.MkdirAll.
func (m *MemFS) MkdirAll(p string, mode fs.FileMode) error {
	parts, err := normalize(p)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.root
	for _, part := range parts {
		child, ok := cur.Children[part]
		if !ok {
			child = &Node{
				Name:     part,
				IsDir:    true,
				Mode:     mode | fs.ModeDir,
				ModTime:  time.Now(),
				Children: make(map[string]*Node),
			}
			cur.Children[part] = child
		} else if !child.IsDir {
			return ErrNotDir
		}
		cur = child
	}
	return nil
}

// Write creates or overwrites a file with the given content.
func (m *MemFS) Write(p string, data []byte, mode fs.FileMode) error {
	parts, err := normalize(p)
	if err != nil {
		return err
	}
	if len(parts) == 0 {
		return ErrIsDir
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	parent, name, err := m.walkParent(parts)
	if err != nil {
		return err
	}
	var oldSize int64
	if existing, ok := parent.Children[name]; ok {
		if existing.IsDir {
			return ErrIsDir
		}
		oldSize = int64(len(existing.Data))
		// Wipe old buffer before drop.
		zeroBytes(existing.Data)
	}
	newSize := int64(len(data))
	if m.quota > 0 && m.used-oldSize+newSize > m.quota {
		return ErrQuota
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	parent.Children[name] = &Node{
		Name:    name,
		IsDir:   false,
		Mode:    mode &^ fs.ModeDir,
		ModTime: time.Now(),
		Data:    buf,
	}
	parent.ModTime = time.Now()
	m.used = m.used - oldSize + newSize
	return nil
}

// Read returns a copy of the file contents.
func (m *MemFS) Read(p string) ([]byte, error) {
	parts, err := normalize(p)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, err := m.walk(parts)
	if err != nil {
		return nil, err
	}
	if n.IsDir {
		return nil, ErrIsDir
	}
	out := make([]byte, len(n.Data))
	copy(out, n.Data)
	return out, nil
}

// Remove deletes a file or empty directory.
func (m *MemFS) Remove(p string) error {
	parts, err := normalize(p)
	if err != nil {
		return err
	}
	if len(parts) == 0 {
		return ErrInvalidPath
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	parent, name, err := m.walkParent(parts)
	if err != nil {
		return err
	}
	child, ok := parent.Children[name]
	if !ok {
		return ErrNotFound
	}
	if child.IsDir && len(child.Children) > 0 {
		return errors.New("valetfs: directory not empty")
	}
	if !child.IsDir {
		m.used -= int64(len(child.Data))
		zeroBytes(child.Data)
	}
	delete(parent.Children, name)
	parent.ModTime = time.Now()
	return nil
}

// Stat returns metadata about the node at p.
func (m *MemFS) Stat(p string) (*Node, error) {
	parts, err := normalize(p)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, err := m.walk(parts)
	if err != nil {
		return nil, err
	}
	// Return a shallow copy without Data/Children to avoid leaking state.
	cp := *n
	cp.Data = nil
	cp.Children = nil
	return &cp, nil
}

// List returns the names of children in directory p, sorted.
func (m *MemFS) List(p string) ([]string, error) {
	parts, err := normalize(p)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, err := m.walk(parts)
	if err != nil {
		return nil, err
	}
	if !n.IsDir {
		return nil, ErrNotDir
	}
	names := make([]string, 0, len(n.Children))
	for k := range n.Children {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, nil
}

// Snapshot returns a deep copy of every (path, content) pair.
// Useful for the sync layer when constructing diffs.
func (m *MemFS) Snapshot() map[string][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string][]byte)
	var walk func(prefix string, n *Node)
	walk = func(prefix string, n *Node) {
		if !n.IsDir {
			buf := make([]byte, len(n.Data))
			copy(buf, n.Data)
			out[prefix] = buf
			return
		}
		for name, child := range n.Children {
			child := child
			next := path.Join(prefix, name)
			walk(next, child)
		}
	}
	walk("/", m.root)
	return out
}

// Wipe zero-fills every file body and drops the tree. Call this on shutdown
// before releasing the process so plaintext token material does not survive
// in heap garbage waiting to be collected.
func (m *MemFS) Wipe() {
	m.mu.Lock()
	defer m.mu.Unlock()
	var walk func(n *Node)
	walk = func(n *Node) {
		if n == nil {
			return
		}
		if !n.IsDir {
			zeroBytes(n.Data)
			n.Data = nil
			return
		}
		for _, c := range n.Children {
			walk(c)
		}
		n.Children = nil
	}
	walk(m.root)
	m.root = &Node{
		Name:     "/",
		IsDir:    true,
		Mode:     0o755 | fs.ModeDir,
		ModTime:  time.Now(),
		Children: make(map[string]*Node),
	}
	m.used = 0
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
