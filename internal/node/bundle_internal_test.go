package node

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/anomalyco/valet-fs/internal/rpc"
	"github.com/anomalyco/valet-fs/internal/vfs"
)

func call(t *testing.T, n *MemoryNode, method string, params map[string]any) rpc.Message {
	t.Helper()
	raw, _ := json.Marshal(rpc.Message{V: 1, ID: "x", Type: rpc.TypeReq, Method: method, Params: params})
	reply, isReq := n.disp.Dispatch(raw)
	if !isReq {
		t.Fatalf("%s not treated as a request", method)
	}
	m, err := rpc.Decode(reply)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func newTestNode() (*MemoryNode, *vfs.MemFS) {
	fs := vfs.New(0)
	return New(Config{FS: fs, Mounted: func() bool { return true }}), fs
}

func sampleFiles(n int, size int) []bundleFile {
	out := make([]bundleFile, n)
	for i := range out {
		d := make([]byte, size)
		_, _ = rand.Read(d[:size/4]) // partly random, partly zero: compressible but not trivially
		out[i] = bundleFile{Path: fmt.Sprintf("/keys/k%03d.env", i), Data: d}
	}
	return out
}

func pushBundle(t *testing.T, n *MemoryNode, wire []byte, id string) rpc.Message {
	t.Helper()
	var last rpc.Message
	for seq := 0; seq*ChunkSize < len(wire) || seq == 0; seq++ {
		end := (seq + 1) * ChunkSize
		if end > len(wire) {
			end = len(wire)
		}
		isLast := end == len(wire)
		last = call(t, n, rpc.MethodBundle, map[string]any{
			"xfer": id, "seq": seq, "last": isLast, "enc": EncGzip,
			"data_b64": base64.StdEncoding.EncodeToString(wire[seq*ChunkSize : end]),
		})
		if !last.OK || isLast {
			break
		}
	}
	return last
}

func TestStatusAdvertisesGzip(t *testing.T) {
	n, _ := newTestNode()
	m := call(t, n, rpc.MethodStatus, nil)
	enc, _ := m.Result["encodings"].([]any)
	if len(enc) != 1 || enc[0] != "gzip" {
		t.Fatalf("encodings = %v", m.Result["encodings"])
	}
}

func TestBundlePushAppliesOnlyOnLastChunk(t *testing.T) {
	n, fs := newTestNode()
	files := sampleFiles(40, 8000) // ~320 KB raw, several chunks
	wire, _, err := EncodeBundle(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) <= ChunkSize {
		t.Fatalf("want a multi-chunk bundle, got %d bytes", len(wire))
	}
	// First chunk alone writes nothing.
	m := call(t, n, rpc.MethodBundle, map[string]any{"xfer": "a", "seq": 0, "last": false, "enc": "gzip",
		"data_b64": base64.StdEncoding.EncodeToString(wire[:ChunkSize])})
	if !m.OK || len(fs.Manifest()) != 0 {
		t.Fatalf("partial bundle touched the fs: ok=%v err=%s n=%d", m.OK, m.Err, len(fs.Manifest()))
	}
	m = pushBundle(t, n, wire, "b")
	if !m.OK {
		t.Fatalf("push failed: %s", m.Err)
	}
	if got, _ := toFloat(m.Result["written"]); int(got) != 40 {
		t.Fatalf("written = %v", m.Result["written"])
	}
	for _, f := range files {
		got, err := fs.Read(f.Path)
		if err != nil || !bytes.Equal(got, f.Data) {
			t.Fatalf("%s did not round-trip", f.Path)
		}
	}
}

func TestBundleRejectsOutOfOrderAndUnknownEncoding(t *testing.T) {
	n, _ := newTestNode()
	m := call(t, n, rpc.MethodBundle, map[string]any{"xfer": "a", "seq": 1, "last": true, "enc": "gzip", "data_b64": ""})
	if m.OK {
		t.Fatal("accepted a transfer starting at seq 1")
	}
	m = call(t, n, rpc.MethodBundle, map[string]any{"xfer": "a", "seq": 0, "last": true, "enc": "br", "data_b64": ""})
	if m.OK || !strings.Contains(m.Err, "unsupported encoding") {
		t.Fatalf("accepted unknown encoding: %+v", m)
	}
}

func TestBundleRefusesGzipBomb(t *testing.T) {
	// A wire bundle that inflates past the ceiling must be refused, not
	// inflated into memory.
	big := []bundleFile{{Path: "/x", Data: make([]byte, maxBundleBytes+10)}}
	wire, _, err := EncodeBundle(big)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBundle(wire); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("bomb not refused: %v", err)
	}
}

func TestPullGzipChunks(t *testing.T) {
	n, fs := newTestNode()
	files := sampleFiles(30, 9000)
	var paths []any
	for _, f := range files {
		_ = fs.MkdirAll("/keys", 0o755)
		if err := fs.Write(f.Path, f.Data, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, f.Path)
	}
	m := call(t, n, rpc.MethodPull, map[string]any{"paths": paths, "accept_enc": []any{"gzip"}})
	if !m.OK || m.Result["enc"] != "gzip" || m.Result["blobs"] != nil {
		t.Fatalf("pull offer: %+v", m)
	}
	id, _ := m.Result["xfer"].(string)
	chunks, _ := toFloat(m.Result["chunks"])
	var wire []byte
	for seq := 0; seq < int(chunks); seq++ {
		c := call(t, n, rpc.MethodPullChunk, map[string]any{"xfer": id, "seq": seq})
		if !c.OK {
			t.Fatalf("chunk %d: %s", seq, c.Err)
		}
		b, _ := base64.StdEncoding.DecodeString(c.Result["data_b64"].(string))
		wire = append(wire, b...)
		if last, _ := c.Result["last"].(bool); last != (seq == int(chunks)-1) {
			t.Fatalf("chunk %d last=%v", seq, last)
		}
	}
	got, err := DecodeBundle(wire)
	if err != nil || len(got) != len(files) {
		t.Fatalf("decode: %v, %d files", err, len(got))
	}
	// The transfer is gone once its last chunk was read.
	if c := call(t, n, rpc.MethodPullChunk, map[string]any{"xfer": id, "seq": 0}); c.OK {
		t.Fatal("finished transfer still readable")
	}
}

func TestPullWithoutAcceptEncIsUnchanged(t *testing.T) {
	n, fs := newTestNode()
	_ = fs.Write("/a", []byte("hello"), 0o600)
	m := call(t, n, rpc.MethodPull, map[string]any{"paths": []any{"/a"}})
	blobs, _ := m.Result["blobs"].(map[string]any)
	if m.Result["enc"] != nil || blobs["/a"] != base64.StdEncoding.EncodeToString([]byte("hello")) {
		t.Fatalf("legacy pull changed: %+v", m.Result)
	}
}

func TestTransfersExpire(t *testing.T) {
	x := newTransfers()
	now := time.Unix(1000, 0)
	x.now = func() time.Time { return now }
	id, _ := x.offer([]byte("abc"))
	now = now.Add(transferTimeout + time.Second)
	if _, _, err := x.chunk(id, 0); err == nil {
		t.Fatal("expired transfer still served")
	}
}
