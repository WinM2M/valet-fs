package ws

import "testing"

// The /ws/connect URL carries the role token in its query string. Over plain
// HTTP anyone on the path reads it and can join the session as the vault, which
// means MANIFEST plus PULL over the whole vault.
func TestCheckHubURLRefusesPlaintextOnTheNetwork(t *testing.T) {
	t.Cleanup(func() { SetAllowInsecure(false) })
	SetAllowInsecure(false)

	refused := []string{
		"http://valetfs-signaling.winm2m.workers.dev",
		"http://example.com:8787",
		"ws://10.0.0.5:8787",
		"http://192.168.1.10",
	}
	for _, u := range refused {
		if err := checkHubURL(u); err == nil {
			t.Errorf("plaintext hub accepted: %s", u)
		}
	}

	// Loopback has no network to eavesdrop on: `valetfs hub` and the
	// integration tests live here and must keep working.
	allowed := []string{
		"http://127.0.0.1:8787",
		"http://localhost:8787",
		"http://[::1]:8787",
		"https://valetfs-signaling.winm2m.workers.dev",
		"wss://example.com",
	}
	for _, u := range allowed {
		if err := checkHubURL(u); err != nil {
			t.Errorf("rejected a safe hub %s: %v", u, err)
		}
	}
}

func TestCheckHubURLHonoursTheExplicitOptIn(t *testing.T) {
	t.Cleanup(func() { SetAllowInsecure(false) })
	SetAllowInsecure(true)
	if err := checkHubURL("http://example.com:8787"); err != nil {
		t.Errorf("--insecure-signaling did not take effect: %v", err)
	}
}

func TestCheckHubURLRejectsNonsenseSchemes(t *testing.T) {
	for _, u := range []string{"ftp://example.com", "file:///etc/passwd"} {
		if err := checkHubURL(u); err == nil {
			t.Errorf("accepted %s", u)
		}
	}
}
