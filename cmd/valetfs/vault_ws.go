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
func vaultWSDial(signaling, sid, claimSecret string) (transport.Conn, *rpc.Client, error) {
	conn, daemonPub, hubVersions, err := ws.DialController(signaling, sid, claimSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("ws connect: %w", err)
	}
	// The hub's version list is unauthenticated. Negotiating against it is fine
	// as an opening bid, but the CLI vault re-checks it against what the daemon
	// reports over the encrypted channel; see verifyProtocol.
	if v := rpc.Negotiate(hubVersions, 0); len(hubVersions) > 0 && v == 0 {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("no shared protocol version with this daemon (it offers %v, this build speaks %v)",
			hubVersions, rpc.Supported)
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
		if err := verifyProtocol(cl, hubVersions); err != nil {
			_ = ec.Close()
			return nil, nil, err
		}
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

func vaultWSPair(v *vault.Vault, vdir, signaling, sid, claimSecret string) error {
	conn, cl, err := vaultWSDial(signaling, sid, claimSecret)
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

func vaultWSSync(v *vault.Vault, signaling, sid, claimSecret string) error {
	conn, cl, err := vaultWSDial(signaling, sid, claimSecret)
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

func vaultWSStatus(signaling, sid, claimSecret string) error {
	conn, cl, err := vaultWSDial(signaling, sid, claimSecret)
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
func vaultWSSimple(signaling, sid, method, claimSecret string) error {
	conn, cl, err := vaultWSDial(signaling, sid, claimSecret)
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

// verifyProtocol compares the version list the hub handed out against the one
// the daemon reports over the encrypted channel. They come from the same daemon
// but by different routes, and only the second is authenticated, so a
// disagreement means the hub edited the offer — the move that would push a
// session onto an older, weaker protocol.
//
// A daemon too old to report the list at all is not an attack; it is simply v1,
// and it says so by omission.
func verifyProtocol(cl *rpc.Client, hubVersions []int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := cl.Call(ctx, rpc.MethodStatus, nil)
	if err != nil {
		return fmt.Errorf("protocol check: %w", err)
	}
	raw, ok := res.Result["protocol_versions"].([]any)
	if !ok {
		return nil // pre-v1-negotiation daemon
	}
	actual := make([]int, 0, len(raw))
	for _, v := range raw {
		if f, ok := v.(float64); ok {
			actual = append(actual, int(f))
		}
	}
	if len(hubVersions) > 0 && !sameVersions(hubVersions, actual) {
		return fmt.Errorf("protocol downgrade detected: the hub advertised %v but the daemon reports %v over the encrypted channel; refusing to continue",
			hubVersions, actual)
	}
	if rpc.Negotiate(actual, 0) == 0 {
		return fmt.Errorf("no shared protocol version (daemon offers %v, this build speaks %v)", actual, rpc.Supported)
	}
	return nil
}

func sameVersions(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[int]int{}
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
