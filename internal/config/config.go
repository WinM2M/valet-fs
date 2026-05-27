// Package config handles CLI flags and environment variable parsing for valetd.
package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
)

// Config holds runtime configuration for the daemon.
type Config struct {
	// Dev enables development mode (no WebRTC, local HTTP control API).
	Dev bool

	// MountPoint is the path where the in-memory VFS will be mounted.
	MountPoint string

	// DevAPIAddr is the address the local control HTTP server listens on in --dev mode.
	DevAPIAddr string

	// SignalingURL is the Cloudflare Worker signaling endpoint for production mode.
	SignalingURL string

	// GitTempDir is the path used for the ephemeral go-git diff repository.
	// Only diffs (no plaintext token bodies) are written here.
	GitTempDir string

	// QuotaBytes is the per-cluster size limit enforced by the VFS.
	QuotaBytes int64
}

// Load parses CLI flags and merges environment variables (.env supported).
func Load(args []string) (*Config, error) {
	// Load .env silently if present; CLI/env precedence handled later.
	_ = godotenv.Load()

	fs := flag.NewFlagSet("valetd", flag.ContinueOnError)

	cfg := &Config{}
	fs.BoolVar(&cfg.Dev, "dev", false, "Run in development mode (no WebRTC, local HTTP control API)")
	fs.StringVar(&cfg.MountPoint, "mount", defaultEnv("VALETFS_MOUNT", defaultMount()), "VFS mount point")
	fs.StringVar(&cfg.DevAPIAddr, "dev-addr", defaultEnv("VALETFS_DEV_ADDR", "127.0.0.1:8080"), "Dev mode control API address")
	fs.StringVar(&cfg.SignalingURL, "signaling", defaultEnv("VALETFS_SIGNALING", ""), "Cloudflare Worker signaling URL")
	fs.StringVar(&cfg.GitTempDir, "git-dir", defaultEnv("VALETFS_GIT_DIR", defaultGitDir()), "Ephemeral go-git diff directory")

	var quotaMB int64
	fs.Int64Var(&quotaMB, "quota-mb", 5, "Cluster quota in megabytes")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	cfg.QuotaBytes = quotaMB * 1024 * 1024

	if cfg.MountPoint == "" {
		return nil, fmt.Errorf("mount point must not be empty")
	}
	return cfg, nil
}

func defaultEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func defaultMount() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".valetfs", "mnt")
	}
	return "/tmp/valetfs-mnt"
}

func defaultGitDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".valetfs", "git")
	}
	return "/tmp/valetfs-git"
}
