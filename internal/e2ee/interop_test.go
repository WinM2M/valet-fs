package e2ee

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// Cross-language interop with the JS (mobile) e2ee implementation. Gated by
// VALETFS_INTEROP so it does not run in the normal suite.
//
//   VALETFS_INTEROP=write go test ./internal/e2ee -run TestInteropWrite
//   node /tmp/e2ee_interop.mjs
//   VALETFS_INTEROP=read  go test ./internal/e2ee -run TestInteropRead

func TestInteropWrite(t *testing.T) {
	if os.Getenv("VALETFS_INTEROP") != "write" {
		t.Skip("set VALETFS_INTEROP=write")
	}
	d, _ := Generate()
	c, _ := Generate()
	key, err := deriveKey(d.Priv, c.Pub) // daemon derives from controller pub
	if err != nil {
		t.Fatal(err)
	}
	s, _ := newSession(key)
	msg := `{"hello":"from-go"}`
	frame, _ := s.seal([]byte(msg))
	vec := map[string]string{
		"keyB64":   base64.StdEncoding.EncodeToString(key),
		"cPrivB64": base64.StdEncoding.EncodeToString(c.Priv[:]),
		"dPubB64":  d.PubB64(),
		"goFrame":  frame,
		"msg":      msg,
	}
	b, _ := json.Marshal(vec)
	if err := os.WriteFile("/tmp/vec.json", b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInteropRead(t *testing.T) {
	if os.Getenv("VALETFS_INTEROP") != "read" {
		t.Skip("set VALETFS_INTEROP=read")
	}
	b, err := os.ReadFile("/tmp/jsvec.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	_ = json.Unmarshal(b, &v)
	key, _ := base64.StdEncoding.DecodeString(v["keyB64"])
	s, _ := newSession(key)
	pt, err := s.open(v["jsFrame"])
	if err != nil {
		t.Fatalf("Go failed to open JS-sealed frame: %v", err)
	}
	if string(pt) != v["msg2"] {
		t.Fatalf("mismatch: %q != %q", pt, v["msg2"])
	}
}
