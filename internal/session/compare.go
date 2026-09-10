package session

import "crypto/subtle"

// subtleEqual compares two keys in constant time. They are public keys, so this
// is not strictly required, but comparing anything key-shaped in variable time
// invites the habit of doing it where it does matter.
func subtleEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
