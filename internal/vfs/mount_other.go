//go:build !linux && !windows

package vfs

import "errors"

// stubMounter exists so the package compiles on platforms we do not support yet.
type stubMounter struct{}

// NewMounter returns a stub Mounter on unsupported platforms.
func NewMounter(_ *MemFS) Mounter { return &stubMounter{} }

// PreUnmount is a no-op on unsupported platforms.
func PreUnmount(_ string) {}

func (*stubMounter) Mount(string) error { return errors.New("valetfs: platform not supported") }
func (*stubMounter) Unmount() error     { return nil }
func (*stubMounter) Backend() string    { return "none" }
