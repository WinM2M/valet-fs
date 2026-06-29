// Package config handles CLI flags and environment variable parsing for valetd.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

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

	// ControlToken authenticates local control API and CLI calls.
	ControlToken string

	// RuntimeDir stores runtime state files (ports/tokens/urls) for local CLI.
	RuntimeDir string

	// WebdavAddr is the bind address for the always-on WebDAV server.
	// Default uses an ephemeral loopback port.
	WebdavAddr string

	// WebdavDisabled disables the WebDAV server when true.
	WebdavDisabled bool

	// SignalingURL is the Cloudflare Worker signaling endpoint for production mode.
	SignalingURL string

	// GitTempDir is the path used for the ephemeral go-git diff repository.
	// Only diffs (no plaintext token bodies) are written here.
	GitTempDir string

	// QuotaBytes is the per-cluster size limit enforced by the VFS.
	QuotaBytes int64

	// RecordRuntimeState controls whether runtime.json is updated.
	RecordRuntimeState bool

	// Transport selects the control-plane transport: "webrtc" (legacy P2P) or
	// "ws" (WebSocket session hub / Durable Object).
	Transport string

	// GraceSeconds is how long the VFS stays mounted after the vault peer goes
	// offline before auto-locking (ws transport). 0 = lock immediately.
	GraceSeconds int
}

// Load parses CLI flags and merges environment variables (.env supported).
func Load(args []string) (*Config, error) {
	// Load .env silently if present; CLI/env precedence handled later.
	_ = godotenv.Load()

	fs := flag.NewFlagSet("valetd", flag.ContinueOnError)

	cfg := &Config{}
	fs.BoolVar(&cfg.Dev, "dev", false, "Run in development mode (no WebRTC, local HTTP control API)")
	fs.StringVar(&cfg.MountPoint, "mount", defaultEnv("VALETFS_MOUNT", defaultMount()), "VFS mount point")
	fs.StringVar(&cfg.DevAPIAddr, "dev-addr", defaultEnv("VALETFS_DEV_ADDR", "127.0.0.1:0"), "Local control API address")
	fs.StringVar(&cfg.ControlToken, "control-token", defaultEnv("VALETFS_CONTROL_TOKEN", ""), "Local control API token (optional; random if empty)")
	fs.StringVar(&cfg.RuntimeDir, "runtime-dir", defaultEnv("VALETFS_RUNTIME_DIR", defaultRuntimeDir()), "Runtime state directory")
	fs.StringVar(&cfg.WebdavAddr, "webdav-addr", defaultEnv("VALETFS_WEBDAV_ADDR", "127.0.0.1:0"), "WebDAV listen address")
	fs.BoolVar(&cfg.WebdavDisabled, "webdav-disabled", defaultEnvBool("VALETFS_WEBDAV_DISABLED", false), "Disable WebDAV server")
	fs.StringVar(&cfg.SignalingURL, "signaling", defaultEnv("VALETFS_SIGNALING", "https://valetfs-signaling.winm2m.workers.dev"), "Cloudflare Worker signaling URL")
	fs.StringVar(&cfg.GitTempDir, "git-dir", defaultEnv("VALETFS_GIT_DIR", defaultGitDir()), "Ephemeral go-git diff directory")

	fs.StringVar(&cfg.Transport, "transport", defaultEnv("VALETFS_TRANSPORT", "webrtc"), "Control-plane transport: webrtc|ws")
	fs.IntVar(&cfg.GraceSeconds, "grace", defaultEnvInt("VALETFS_GRACE", 300), "Seconds to keep VFS mounted after vault goes offline (ws transport; 0 = immediate)")

	var quotaMB int64
	fs.Int64Var(&quotaMB, "quota-mb", 5, "Cluster quota in megabytes")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	cfg.QuotaBytes = quotaMB * 1024 * 1024

	if cfg.MountPoint == "" {
		return nil, fmt.Errorf("mount point must not be empty")
	}
	if cfg.ControlToken == "" {
		tok, err := randomToken(16)
		if err != nil {
			return nil, fmt.Errorf("generate control token: %w", err)
		}
		cfg.ControlToken = tok
	}
	cfg.RecordRuntimeState = cfg.DevAPIAddr == "127.0.0.1:0"
	return cfg, nil
}

func defaultEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func defaultEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func defaultEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v == "1" || v == "true" || v == "TRUE" || v == "yes" || v == "YES"
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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

func defaultRuntimeDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".valetfs", "run")
	}
	return "/tmp/valetfs-run"
}
