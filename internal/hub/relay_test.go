package hub

import "testing"

// Presence drives the daemon's grace timer: peer_offline starts the countdown
// that unmounts and wipes, peer_online cancels it. The relay used to forward
// frames verbatim, so either peer could forge them.
func TestIsSystemFrameCatchesForgedPresence(t *testing.T) {
	forged := [][]byte{
		[]byte(`{"sys":"peer_offline","role":"vault"}`),
		[]byte(`{"sys":"peer_online","role":"vault"}`),
		[]byte(`{"sys":"ka"}`),
		// Key order is the sender's choice, so a prefix check would miss this.
		[]byte(`{"role":"vault","sys":"peer_offline"}`),
		// Padding must not buy a bypass either.
		[]byte(`{"pad":"` + string(make([]byte, 0)) + `aaaaaaaaaaaaaaaa","sys":"peer_offline","role":"vault"}`),
		[]byte(`{"sys":null}`),
	}
	for _, f := range forged {
		if !isSystemFrame(f) {
			t.Errorf("forged presence relayed: %s", f)
		}
	}

	legitimate := [][]byte{
		[]byte(`{"v":1,"type":"REQ","method":"STATUS"}`),
		[]byte(`{"enc":"YmFzZTY0"}`),
		[]byte(`{"kx":"hello","pub":"AAAA"}`),
		[]byte(`not json at all`),
		[]byte(``),
	}
	for _, f := range legitimate {
		if isSystemFrame(f) {
			t.Errorf("app frame wrongly dropped: %s", f)
		}
	}
}
