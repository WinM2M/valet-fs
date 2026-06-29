package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anomalyco/valet-fs/internal/e2ee"
	"github.com/anomalyco/valet-fs/internal/rpc"
	"github.com/anomalyco/valet-fs/internal/transport"
	"github.com/anomalyco/valet-fs/internal/transport/ws"
	"github.com/anomalyco/valet-fs/internal/vault"
)

// vaultWSDial claims and connects to a session over the WebSocket hub (Durable
// Object), returning a ready rpc.Client. If the daemon published an E2EE public
// key, the connection is end-to-end encrypted (the hub sees only ciphertext).
func vaultWSDial(signaling, sid string) (transport.Conn, *rpc.Client, error) {
	conn, daemonPub, err := ws.DialController(signaling, sid)
	if err != nil {
		return nil, nil, fmt.Errorf("ws connect: %w", err)
	}
	if daemonPub != "" {
		kp, err := e2ee.Generate()
		if err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("e2ee keygen: %w", err)
		}
		ec, err := e2ee.WrapController(conn, kp, daemonPub)
		if err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("e2ee handshake: %w", err)
		}
		cl := rpc.NewClient(ec)
		ec.Start()
		return ec, cl, nil
	}
	// Legacy / no-E2EE daemon: plaintext over the hub.
	cl := rpc.NewClient(conn)
	conn.Start()
	return conn, cl, nil
}

func vaultWSCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// vaultWSPushAll writes every vault entry into the remote daemon FS.
func vaultWSPushAll(cl *rpc.Client, v *vault.Vault) error {
	for _, e := range v.List("/") {
		b, err := v.Read(e.Path)
		if err != nil {
			return err
		}
		ctx, cancel := vaultWSCtx()
		_, err = cl.Call(ctx, rpc.MethodWrite, map[string]any{
			"path":        e.Path,
			"content_b64": base64.StdEncoding.EncodeToString(b),
		})
		cancel()
		if err != nil {
			return fmt.Errorf("push %s: %w", e.Path, err)
		}
	}
	return nil
}

func vaultWSPair(v *vault.Vault, vdir, signaling, sid string) error {
	conn, cl, err := vaultWSDial(signaling, sid)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := vaultWSPushAll(cl, v); err != nil {
		return err
	}
	now := time.Now().UTC()
	_ = vault.SaveSession(vdir, vault.SessionRecord{
		SessionID: sid, SignalingURL: signaling, PairedAt: now, LastSeen: now,
	})
	_, _ = fmt.Fprintln(os.Stdout, "paired and pushed vault entries (ws)")
	return nil
}

func vaultWSSync(v *vault.Vault, signaling, sid string) error {
	conn, cl, err := vaultWSDial(signaling, sid)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := vaultWSPushAll(cl, v); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(os.Stdout, "synced vault entries (ws)")
	return nil
}

func vaultWSStatus(signaling, sid string) error {
	conn, cl, err := vaultWSDial(signaling, sid)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := vaultWSCtx()
	defer cancel()
	m, err := cl.Call(ctx, rpc.MethodStatus, nil)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "remote status: %+v\n", m.Result)
	return nil
}

// vaultWSSimple issues a single no-param method (UNMOUNT/LOCK) and reports.
func vaultWSSimple(signaling, sid, method string) error {
	conn, cl, err := vaultWSDial(signaling, sid)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := vaultWSCtx()
	defer cancel()
	if _, err := cl.Call(ctx, method, nil); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "%s ok (ws)\n", strings.ToLower(method))
	return nil
}
