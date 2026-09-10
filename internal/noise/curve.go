// Package noise holds ValetFS's conformance tests against the official Noise
// Protocol test vectors, plus the small helpers they need.
package noise

import "golang.org/x/crypto/curve25519"

// curvePublic derives an X25519 public key from a private scalar.
func curvePublic(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}
