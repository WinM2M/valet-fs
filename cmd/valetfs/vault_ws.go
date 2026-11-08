package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/anomalyco/valet-fs/internal/rpc"
	"github.com/anomalyco/valet-fs/internal/session"
	"github.com/anomalyco/valet-fs/internal/transport"
	"github.com/anomalyco/valet-fs/internal/transport/ws"
	"github.com/anomalyco/valet-fs/internal/vault"
)

// vaultWSTarget names the session a CLI vault command talks to and what it may
// trust about the daemon at the other end.
type vaultWSTarget struct {
	signaling, sid, claimSecret string
	vdir                        string
	// daemonPub and daemonFP are the daemon's identity as the person got it
	// from the daemon itself, not from the hub: a base64 key or the short
	// fingerprint the daemon prints at startup. Either one is enough.
	daemonPub, daemonFP string
}

// vaultWSDial claims the session over the hub and opens a v2 session with the
// daemon, returning a ready rpc.Client.
//
// The hub is not trusted with the daemon's identity. The key it reports is
// accepted only if it matches what the person supplied (--daemon-pub or
// --daemon-fingerprint), what this vault recorded the first time it used the
// session, or what the person confirms at a prompt. There is no fallback to an
// unauthenticated channel: if any of that fails, nothing is sent.
func vaultWSDial(t vaultWSTarget) (transport.Conn, *rpc.Client, error) {
	conn, info, err := ws.DialControllerInfo(t.signaling, t.sid, t.claimSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("ws connect: %w", err)
	}
	fail := func(format string, a ...any) (transport.Conn, *rpc.Client, error) {
		_ = conn.Close()
		return nil, nil, fmt.Errorf(format, a...)
	}
	// The hub's version list is unauthenticated. Negotiating against it is fine
	// as an opening bid, but the CLI vault re-checks it against what the daemon
	// reports over the encrypted channel; see verifyProtocol.
	if v := rpc.Negotiate(info.Versions, 0); len(info.Versions) > 0 && v == 0 {
		return fail("no shared protocol version with this daemon (it offers %v, this build speaks %v)",
			info.Versions, rpc.Supported)
	}
	if info.DaemonPubV2 == "" {
		return fail("this daemon does not publish a v2 identity; update it (the unauthenticated v1 protocol is no longer spoken)")
	}
	hubPub, err := session.ParsePub(info.DaemonPubV2)
	if err != nil {
		return fail("the hub reported an unusable daemon key: %v", err)
	}
	if err := confirmDaemonIdentity(t, hubPub); err != nil {
		return fail("%v", err)
	}
	static, _, err := session.LoadOrGenerateStatic(filepath.Join(t.vdir, vaultIdentityFile))
	if err != nil {
		return fail("vault identity: %v", err)
	}
	vc, err := session.NewVault(session.Config{
		Inner: conn, SessionID: t.sid, Static: static, PeerStatic: hubPub,
	})
	if err != nil {
		return fail("session: %v", err)
	}
	cl := rpc.NewClient(vc)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := vc.Start(ctx); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("handshake with the daemon failed (is this vault's identity authorised there? "+
			"run `valetfs vault identity` here, then `valetfs vaults authorize <that key>` on the daemon's machine): %w", err)
	}
	if err := verifyProtocol(cl, info.Versions); err != nil {
		_ = vc.Close()
		return nil, nil, err
	}
	rememberDaemon(t, hubPub)
	return vc, cl, nil
}

// vaultIdentityFile holds this vault's long-lived Noise key inside the vault
// directory.
const vaultIdentityFile = "identity.key"

// confirmDaemonIdentity decides whether the key the hub reported is the daemon's.
func confirmDaemonIdentity(t vaultWSTarget, hubPub []byte) error {
	if t.daemonPub != "" {
		want, err := session.ParsePub(t.daemonPub)
		if err != nil {
			return fmt.Errorf("--daemon-pub: %w", err)
		}
		if !bytes.Equal(want, hubPub) {
			return fmt.Errorf("the hub's daemon key does not match --daemon-pub; refusing (the hub may be substituting its own key)")
		}
		return nil
	}
	if t.daemonFP != "" {
		if normaliseFingerprint(t.daemonFP) != normaliseFingerprint(session.Fingerprint(hubPub)) {
			return fmt.Errorf("the hub's daemon key (fingerprint %s) does not match --daemon-fingerprint; refusing "+
				"(the hub may be substituting its own key)", session.Fingerprint(hubPub))
		}
		return nil
	}
	if rec, err := vault.LoadSession(t.vdir, t.sid); err == nil && rec.DaemonPubV2 != "" {
		if rec.DaemonPubV2 != session.PubB64(hubPub) {
			return fmt.Errorf("the daemon's identity changed since this vault first used the session "+
				"(was %s, now %s); refusing. If the daemon was reinstalled, pair again with a new session",
				fingerprintOfB64(rec.DaemonPubV2), session.Fingerprint(hubPub))
		}
		return nil
	}
	// First contact, with nothing the hub did not supply. Ask a person.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("first use of this session: the daemon's identity must be confirmed. Pass " +
			"--daemon-fingerprint <fingerprint> (printed by the daemon at startup) or --daemon-pub, or run from a terminal")
	}
	_, _ = fmt.Fprintf(os.Stdout, "The hub says this daemon's identity fingerprint is\n\n    %s\n\n"+
		"Compare it with the line \"Daemon identity fingerprint\" the daemon printed when it started. "+
		"If they differ, the hub is not passing your connection through.\nTrust it? [y/N] ", session.Fingerprint(hubPub))
	var answer string
	_, _ = fmt.Fscanln(os.Stdin, &answer)
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		return fmt.Errorf("not confirmed; nothing was sent")
	}
	return nil
}

func normaliseFingerprint(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "", ":", "").Replace(strings.TrimSpace(s)))
}

func fingerprintOfB64(b64 string) string {
	pub, err := session.ParsePub(b64)
	if err != nil {
		return "unknown"
	}
	return session.Fingerprint(pub)
}

// rememberDaemon records the daemon's key against the session after a handshake
// that used it succeeded, so later runs can hold the daemon to the same key.
func rememberDaemon(t vaultWSTarget, pub []byte) {
	rec, err := vault.LoadSession(t.vdir, t.sid)
	if err != nil || rec == nil {
		now := time.Now().UTC()
		rec = &vault.SessionRecord{SessionID: t.sid, SignalingURL: t.signaling, PairedAt: now, LastSeen: now}
	}
	rec.DaemonPubV2 = session.PubB64(pub)
	rec.LastSeen = time.Now().UTC()
	_ = vault.SaveSession(t.vdir, *rec)
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

func vaultWSPair(v *vault.Vault, t vaultWSTarget) error {
	conn, cl, err := vaultWSDial(t)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := vaultWSPushAll(cl, v); err != nil {
		return err
	}
	// vaultWSDial already recorded the daemon's key; keep it and stamp the pairing.
	rec, lerr := vault.LoadSession(t.vdir, t.sid)
	now := time.Now().UTC()
	if lerr != nil || rec == nil {
		rec = &vault.SessionRecord{SessionID: t.sid}
	}
	rec.SignalingURL, rec.PairedAt, rec.LastSeen = t.signaling, now, now
	_ = vault.SaveSession(t.vdir, *rec)
	_, _ = fmt.Fprintln(os.Stdout, "paired and pushed vault entries (ws)")
	return nil
}

func vaultWSSync(v *vault.Vault, t vaultWSTarget) error {
	conn, cl, err := vaultWSDial(t)
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

func vaultWSStatus(t vaultWSTarget) error {
	conn, cl, err := vaultWSDial(t)
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
func vaultWSSimple(t vaultWSTarget, method string) error {
	conn, cl, err := vaultWSDial(t)
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
