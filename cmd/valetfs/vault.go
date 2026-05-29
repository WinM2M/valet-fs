package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anomalyco/valet-fs/internal/vault"
	"github.com/anomalyco/valet-fs/internal/webrtc"
	"golang.org/x/term"
)

func runVault(args []string) error {
	fs := flag.NewFlagSet("vault", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	vdirFlag := fs.String("vault-dir", defaultVaultDir(), "vault directory")
	passwordFile := fs.String("password-file", "", "password file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	args = fs.Args()
	if len(args) == 0 {
		return fmt.Errorf("usage: valetfs vault <init|add|ls|rm|pair|sync|unmount|status>")
	}
	vdir := *vdirFlag
	vault.SetPassphraseProvider(func() string {
		if *passwordFile != "" {
			b, err := os.ReadFile(*passwordFile)
			if err == nil {
				return strings.TrimSpace(string(b))
			}
		}
		if p := os.Getenv("VALETFS_VAULT_PASSWORD"); p != "" {
			return p
		}
		if term.IsTerminal(int(os.Stdin.Fd())) {
			_, _ = fmt.Fprint(os.Stdout, "Vault passphrase: ")
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			_, _ = fmt.Fprintln(os.Stdout)
			if err == nil {
				return strings.TrimSpace(string(pw))
			}
		}
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
		return "valetfs-default-dev-passphrase"
	})
	v, err := vault.Open(vdir)
	if err != nil {
		return err
	}
	switch args[0] {
	case "init":
		_, err := os.Stat(filepath.Join(vdir, "manifest.json"))
		if err == nil {
			_, _ = fmt.Fprintln(os.Stdout, "vault already initialized")
			return nil
		}
		_, _ = fmt.Fprintln(os.Stdout, "vault initialized at", vdir)
		return nil
	case "add":
		if len(args) < 3 {
			return fmt.Errorf("usage: valetfs vault add <host-path> <fs-path>")
		}
		if err := v.Add(args[1], args[2]); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(os.Stdout, "added", args[2])
		return nil
	case "ls":
		prefix := "/"
		if len(args) > 1 {
			prefix = args[1]
		}
		for _, e := range v.List(prefix) {
			_, _ = fmt.Fprintf(os.Stdout, "%s (%d bytes)\n", e.Path, e.Size)
		}
		return nil
	case "rm":
		if len(args) < 2 {
			return fmt.Errorf("usage: valetfs vault rm <fs-path>")
		}
		return v.Remove(args[1])
	case "pair":
		if len(args) < 2 {
			return fmt.Errorf("usage: valetfs vault pair <session_id> [--signaling URL]")
		}
		sid := args[1]
		signaling := os.Getenv("VALETFS_SIGNALING")
		for i := 2; i < len(args); i++ {
			if args[i] == "--signaling" && i+1 < len(args) {
				signaling = args[i+1]
				i++
			}
		}
		if signaling == "" {
			return fmt.Errorf("missing signaling URL (--signaling or VALETFS_SIGNALING)")
		}
		p, err := webrtc.NewController()
		if err != nil {
			return err
		}
		defer p.Close()
		openCh := make(chan struct{}, 1)
		p.OnOpen(func() { select { case openCh <- struct{}{}: default: } })
		if err := p.Join(signaling, sid); err != nil {
			return err
		}
		select {
		case <-openCh:
		case <-time.After(5 * time.Second):
		}
		for _, e := range v.List("/") {
			b, err := v.Read(e.Path)
			if err != nil {
				return err
			}
			rpc := webrtc.NewRequest("WRITE", map[string]any{
				"path":    strings.TrimPrefix(e.Path, "/"),
				"content": string(b),
			})
			msg, _ := webrtc.EncodeRPC(rpc)
			if err := p.Send(msg); err != nil {
				return err
			}
		}
		_ = vault.SaveSession(vdir, vault.SessionRecord{SessionID: sid, SignalingURL: signaling, PairedAt: time.Now().UTC(), LastSeen: time.Now().UTC()})
		_, _ = fmt.Fprintln(os.Stdout, "paired and pushed vault entries")
		return nil
	case "unmount":
		if len(args) < 2 {
			return fmt.Errorf("usage: valetfs vault unmount <session_id> [--signaling URL]")
		}
		sid := args[1]
		signaling := os.Getenv("VALETFS_SIGNALING")
		for i := 2; i < len(args); i++ {
			if args[i] == "--signaling" && i+1 < len(args) {
				signaling = args[i+1]
				i++
			}
		}
		if signaling == "" {
			if rec, err := vault.LoadSession(vdir, sid); err == nil {
				signaling = rec.SignalingURL
			}
		}
		if signaling == "" {
			return fmt.Errorf("missing signaling URL")
		}
		p, err := webrtc.NewController()
		if err != nil {
			return err
		}
		defer p.Close()
		if err := p.Join(signaling, sid); err != nil {
			return err
		}
		msg, _ := webrtc.EncodeRPC(webrtc.NewRequest("UNMOUNT", map[string]any{}))
		return p.Send(msg)
	case "sync":
		if len(args) < 2 {
			return fmt.Errorf("usage: valetfs vault sync <session_id> [--signaling URL]")
		}
		sid := args[1]
		signaling := os.Getenv("VALETFS_SIGNALING")
		for i := 2; i < len(args); i++ {
			if args[i] == "--signaling" && i+1 < len(args) {
				signaling = args[i+1]
				i++
			}
		}
		if signaling == "" {
			if rec, err := vault.LoadSession(vdir, sid); err == nil {
				signaling = rec.SignalingURL
			}
		}
		if signaling == "" {
			return fmt.Errorf("missing signaling URL")
		}
		p, err := webrtc.NewController()
		if err != nil {
			return err
		}
		defer p.Close()
		if err := p.Join(signaling, sid); err != nil {
			return err
		}
		for _, e := range v.List("/") {
			b, err := v.Read(e.Path)
			if err != nil {
				return err
			}
			msg, _ := webrtc.EncodeRPC(webrtc.NewRequest("WRITE", map[string]any{"path": strings.TrimPrefix(e.Path, "/"), "content": string(b)}))
			if err := p.Send(msg); err != nil {
				return err
			}
		}
		_, _ = fmt.Fprintln(os.Stdout, "synced vault entries")
		return nil
	case "status":
		if len(args) >= 2 {
			sid := args[1]
			signaling := os.Getenv("VALETFS_SIGNALING")
			for i := 2; i < len(args); i++ {
				if args[i] == "--signaling" && i+1 < len(args) {
					signaling = args[i+1]
					i++
				}
			}
			if signaling == "" {
				if rec, err := vault.LoadSession(vdir, sid); err == nil {
					signaling = rec.SignalingURL
				}
			}
			if signaling == "" {
				return fmt.Errorf("missing signaling URL")
			}
			p, err := webrtc.NewController()
			if err != nil {
				return err
			}
			defer p.Close()
			respCh := make(chan webrtc.RPCMessage, 1)
			p.OnData(func(b []byte) {
				m, err := webrtc.DecodeRPC(b)
				if err == nil && strings.EqualFold(m.Type, "RES") {
					select { case respCh <- m: default: }
				}
			})
			if err := p.Join(signaling, sid); err != nil {
				return err
			}
			req, _ := webrtc.EncodeRPC(webrtc.NewRequest("STATUS", map[string]any{}))
			if err := p.Send(req); err != nil {
				return err
			}
			select {
			case m := <-respCh:
				_, _ = fmt.Fprintf(os.Stdout, "remote status: %+v\n", m.Result)
			case <-time.After(3 * time.Second):
				return fmt.Errorf("timeout waiting remote status")
			}
			return nil
		}
		sessions, err := vault.ListSessions(vdir)
		if err != nil {
			return err
		}
		for _, s := range sessions {
			_, _ = fmt.Fprintf(os.Stdout, "%s %s %s\n", s.SessionID, s.SignalingURL, s.LastSeen.Format(time.RFC3339))
		}
		return nil
	}
	return fmt.Errorf("unknown vault subcommand: %s", args[0])
}

func defaultVaultDir() string {
	if v := os.Getenv("VALETFS_VAULT_DIR"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/valetfs-vault"
	}
	return filepath.Join(home, ".valetfs", "vault")
}
