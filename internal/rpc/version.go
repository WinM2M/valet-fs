package rpc

// Control-plane protocol versions.
//
// Version negotiation is itself an attack surface: the app learns what a daemon
// speaks from the hub's claim response, and the hub is not trusted. A hub that
// claims "this daemon only speaks v1" would push every session onto the older,
// unauthenticated protocol — defeating the point of introducing a newer one.
//
// Nothing can authenticate the offer before a channel exists, so the defence is
// the same one TLS uses: negotiate in the clear, then confirm inside the
// established channel. The daemon reports the same list over the encrypted
// connection in STATUS, and a client that sees a different list from the hub
// knows the hub edited it.
//
// The second half of the defence lives in the client: it pins the highest
// version it has ever seen a given daemon support and refuses to go below it.
const (
	// V1 is the original protocol: X25519 + HKDF + ChaCha20-Poly1305 with an
	// unauthenticated controller. Kept only so the shipped app keeps working
	// while v2 rolls out; M3 removes it.
	V1 = 1
	// V2 is Noise_IK_25519_ChaChaPoly_SHA256 with an authorised vault identity,
	// a key per direction, and frames bound to their session.
	V2 = 2
)

// Supported lists every version this build can speak, ascending.
var Supported = []int{V1, V2}

// Current is the newest version this build speaks.
const Current = V2

// Negotiate picks the highest version both sides support, or 0 when there is no
// overlap. floor rejects anything below a previously observed version, which is
// what stops a hub walking a client backwards.
func Negotiate(peer []int, floor int) int {
	best := 0
	for _, v := range peer {
		if v < floor {
			continue
		}
		for _, own := range Supported {
			if v == own && v > best {
				best = v
			}
		}
	}
	return best
}
