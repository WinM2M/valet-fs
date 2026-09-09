package noise

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/flynn/noise"
)

// Conformance against the official Noise Protocol test vectors.
//
// This test is the precondition for hand-writing the handshake on the app side.
// Without it, "the two implementations agree" only shows they share a
// misunderstanding. With it, each side is measured against the spec as realised
// by two independent generators — cacophony (Haskell) and noise-c (C) — so
// passing means following the protocol rather than inventing one that happens to
// interoperate with itself.

type vector struct {
	Source       string `json:"source"`
	InitPrologue string `json:"init_prologue"`
	InitStatic   string `json:"init_static"`
	InitRemoteS  string `json:"init_remote_static"`
	InitEphem    string `json:"init_ephemeral"`
	RespPrologue string `json:"resp_prologue"`
	RespStatic   string `json:"resp_static"`
	RespEphem    string `json:"resp_ephemeral"`
	HandshakeH   string `json:"handshake_hash"`
	Messages     []struct {
		Payload    string `json:"payload"`
		Ciphertext string `json:"ciphertext"`
	} `json:"messages"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/noise/ik_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(doc.Vectors) < 2 {
		t.Fatalf("want vectors from both generators, got %d", len(doc.Vectors))
	}
	return doc.Vectors
}

func keypair(t *testing.T, privHex string) noise.DHKey {
	t.Helper()
	priv := unhex(t, privHex)
	pub, err := curvePublic(priv)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	return noise.DHKey{Private: priv, Public: pub}
}

func TestIKMatchesOfficialVectors(t *testing.T) {
	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	for _, v := range loadVectors(t) {
		t.Run(v.Source, func(t *testing.T) {
			// Replaying the vector's ephemeral keys is the only way to make a
			// handshake reproducible; Random is where the library takes them from.
			initiator, err := noise.NewHandshakeState(noise.Config{
				CipherSuite:   suite,
				Random:        bytes.NewReader(unhex(t, v.InitEphem)),
				Pattern:       noise.HandshakeIK,
				Initiator:     true,
				Prologue:      unhex(t, v.InitPrologue),
				StaticKeypair: keypair(t, v.InitStatic),
				PeerStatic:    unhex(t, v.InitRemoteS),
			})
			if err != nil {
				t.Fatalf("initiator: %v", err)
			}
			responder, err := noise.NewHandshakeState(noise.Config{
				CipherSuite:   suite,
				Random:        bytes.NewReader(unhex(t, v.RespEphem)),
				Pattern:       noise.HandshakeIK,
				Initiator:     false,
				Prologue:      unhex(t, v.RespPrologue),
				StaticKeypair: keypair(t, v.RespStatic),
			})
			if err != nil {
				t.Fatalf("responder: %v", err)
			}

			// Both WriteMessage and ReadMessage return Split()'s raw (c1, c2)
			// without adjusting for role. Per the spec c1 carries
			// initiator->responder and c2 the other way, so the initiator's send
			// state is c1 and the responder's send state is c2. Getting this
			// backwards still produces correct-looking handshake messages and
			// fails only on the first transport message — which is precisely the
			// kind of mistake these vectors exist to catch.
			var iSend, iRecv, rSend, rRecv *noise.CipherState
			split := func(initiatorSide bool, c1, c2 *noise.CipherState) {
				if c1 == nil {
					return
				}
				if initiatorSide {
					iSend, iRecv = c1, c2
				} else {
					rSend, rRecv = c2, c1
				}
			}

			for i, m := range v.Messages {
				payload := unhex(t, m.Payload)
				want := unhex(t, m.Ciphertext)
				initiatorWrites := i%2 == 0

				var got []byte
				var c1, c2 *noise.CipherState
				switch {
				case iSend == nil: // still handshaking
					if initiatorWrites {
						got, c1, c2, err = initiator.WriteMessage(nil, payload)
					} else {
						got, c1, c2, err = responder.WriteMessage(nil, payload)
					}
					split(initiatorWrites, c1, c2)
				case initiatorWrites:
					got, err = iSend.Encrypt(nil, nil, payload)
				default:
					got, err = rSend.Encrypt(nil, nil, payload)
				}
				if err != nil {
					t.Fatalf("message %d write: %v", i, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("message %d ciphertext mismatch\n got %x\nwant %x", i, got, want)
				}

				// The other side must accept the vector's bytes and recover the
				// payload: matching ciphertext alone would not prove the reader
				// derived the same keys.
				var pt []byte
				switch {
				case iRecv == nil || rRecv == nil: // still handshaking
					if initiatorWrites {
						pt, c1, c2, err = responder.ReadMessage(nil, want)
						split(false, c1, c2)
					} else {
						pt, c1, c2, err = initiator.ReadMessage(nil, want)
						split(true, c1, c2)
					}
				case initiatorWrites:
					pt, err = rRecv.Decrypt(nil, nil, want)
				default:
					pt, err = iRecv.Decrypt(nil, nil, want)
				}
				if err != nil {
					t.Fatalf("message %d read: %v", i, err)
				}
				if !bytes.Equal(pt, payload) {
					t.Fatalf("message %d payload mismatch: got %x want %x", i, pt, payload)
				}
			}

			// The transcript hash binds the whole handshake. Two implementations
			// can agree on every ciphertext and still disagree here if either
			// mixed the transcript wrongly.
			if got := hex.EncodeToString(initiator.ChannelBinding()); got != v.HandshakeH {
				t.Fatalf("handshake hash mismatch\n got %s\nwant %s", got, v.HandshakeH)
			}
			if got := hex.EncodeToString(responder.ChannelBinding()); got != v.HandshakeH {
				t.Fatalf("responder handshake hash mismatch\n got %s\nwant %s", got, v.HandshakeH)
			}
		})
	}
}
