package node

// Compressed bulk transfer.
//
// The original protocol moves one file per WRITE and every requested file in a
// single PULL response. That works, but a vault of forty keys costs forty round
// trips through the hub on a push, and a pull gives the app nothing to measure
// progress against until the one large response lands.
//
// This adds a second path that both sides only take when they know the other
// speaks it:
//
//   - STATUS advertises "encodings": ["gzip"]. STATUS travels over the
//     encrypted channel, so the hub can neither invent the capability nor
//     strip it to force the slow path.
//   - BUNDLE carries a push as gzip-compressed chunks of one bundle. Every
//     chunk names its encoding; nothing is applied until the last one arrives
//     and the whole bundle decodes.
//   - PULL with "accept_enc": ["gzip"] answers with a transfer id instead of
//     the blobs, and the app fetches the chunks with PULL_CHUNK at its own pace.
//     A PULL without accept_enc is answered exactly as before, which is what
//     keeps an older app working against this daemon.
//
// The bundle itself is a flat, length-prefixed list rather than JSON, because
// base64 inside a compressed stream throws away a quarter of what compression
// buys:
//
//	"VFB1" | repeat { u32 path_len | path | u32 data_len | data }   (big endian)

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	EncGzip = "gzip"

	bundleMagic = "VFB1"
	// Raw bytes per chunk. Base64 makes it 64 KiB on the wire, comfortably under
	// any frame limit between here and the hub.
	ChunkSize = 48 * 1024
	// Ceilings that keep a hostile or broken peer from making the daemon hold
	// or inflate an unbounded amount of memory. A vault of secrets is measured
	// in kilobytes; these are orders of magnitude above that.
	maxWireBytes    = 32 << 20
	maxBundleBytes  = 64 << 20
	maxBundleFiles  = 10000
	maxPathLen      = 4096
	transferTimeout = 60 * time.Second
)

// Encodings is what STATUS advertises.
var Encodings = []string{EncGzip}

type bundleFile struct {
	Path string
	Data []byte
}

// EncodeBundle packs files and gzips the result.
func EncodeBundle(files []bundleFile) ([]byte, int, error) {
	var raw bytes.Buffer
	raw.WriteString(bundleMagic)
	var n [4]byte
	for _, f := range files {
		binary.BigEndian.PutUint32(n[:], uint32(len(f.Path)))
		raw.Write(n[:])
		raw.WriteString(f.Path)
		binary.BigEndian.PutUint32(n[:], uint32(len(f.Data)))
		raw.Write(n[:])
		raw.Write(f.Data)
	}
	var out bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		return nil, 0, err
	}
	if err := zw.Close(); err != nil {
		return nil, 0, err
	}
	return out.Bytes(), raw.Len(), nil
}

// DecodeBundle gunzips and unpacks, refusing anything past the ceilings.
func DecodeBundle(wire []byte) ([]bundleFile, error) {
	zr, err := gzip.NewReader(bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(zr, maxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if len(raw) > maxBundleBytes {
		return nil, errors.New("bundle: too large")
	}
	if len(raw) < len(bundleMagic) || string(raw[:len(bundleMagic)]) != bundleMagic {
		return nil, errors.New("bundle: bad magic")
	}
	rest := raw[len(bundleMagic):]
	next := func(limit int) ([]byte, error) {
		if len(rest) < 4 {
			return nil, errors.New("bundle: truncated")
		}
		l := int(binary.BigEndian.Uint32(rest))
		rest = rest[4:]
		if l > limit || l > len(rest) {
			return nil, errors.New("bundle: truncated")
		}
		b := rest[:l]
		rest = rest[l:]
		return b, nil
	}
	var files []bundleFile
	for len(rest) > 0 {
		if len(files) >= maxBundleFiles {
			return nil, errors.New("bundle: too many files")
		}
		p, err := next(maxPathLen)
		if err != nil {
			return nil, err
		}
		if len(p) == 0 {
			return nil, errors.New("bundle: empty path")
		}
		d, err := next(maxBundleBytes)
		if err != nil {
			return nil, err
		}
		files = append(files, bundleFile{Path: string(p), Data: d})
	}
	return files, nil
}

type transfer struct {
	buf     []byte
	next    int // next expected seq (inbound) / chunk count (outbound)
	touched time.Time
}

// transfers holds in-flight bundles in both directions. Separate maps so an id
// from one direction can never be used to read or append to the other.
type transfers struct {
	mu  sync.Mutex
	in  map[string]*transfer
	out map[string]*transfer
	now func() time.Time
}

func newTransfers() *transfers {
	return &transfers{in: map[string]*transfer{}, out: map[string]*transfer{}, now: time.Now}
}

func (t *transfers) sweep() {
	now := t.now()
	for _, m := range []map[string]*transfer{t.in, t.out} {
		for id, x := range m {
			if now.Sub(x.touched) > transferTimeout {
				delete(m, id)
			}
		}
	}
}

func newXferID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// appendChunk adds one inbound chunk. It returns the complete wire bundle when
// last is set, and nil otherwise.
func (t *transfers) appendChunk(id string, seq int, last bool, data []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweep()
	x := t.in[id]
	if x == nil {
		if seq != 0 {
			return nil, errors.New("bundle: unknown or expired transfer")
		}
		x = &transfer{}
		t.in[id] = x
	}
	if seq != x.next {
		delete(t.in, id)
		return nil, fmt.Errorf("bundle: chunk %d out of order, expected %d", seq, x.next)
	}
	if len(x.buf)+len(data) > maxWireBytes {
		delete(t.in, id)
		return nil, errors.New("bundle: too large")
	}
	x.buf = append(x.buf, data...)
	x.next++
	x.touched = t.now()
	if !last {
		return nil, nil
	}
	delete(t.in, id)
	return x.buf, nil
}

func (t *transfers) offer(wire []byte) (string, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweep()
	id := newXferID()
	chunks := (len(wire) + ChunkSize - 1) / ChunkSize
	if chunks == 0 {
		chunks = 1
	}
	t.out[id] = &transfer{buf: wire, next: chunks, touched: t.now()}
	return id, chunks
}

func (t *transfers) chunk(id string, seq int) ([]byte, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweep()
	x := t.out[id]
	if x == nil {
		return nil, false, errors.New("pull: unknown or expired transfer")
	}
	if seq < 0 || seq >= x.next {
		return nil, false, fmt.Errorf("pull: chunk %d out of range", seq)
	}
	start := seq * ChunkSize
	end := start + ChunkSize
	if end > len(x.buf) {
		end = len(x.buf)
	}
	last := seq == x.next-1
	x.touched = t.now()
	if last {
		delete(t.out, id)
	}
	return x.buf[start:end], last, nil
}

// acceptsGzip reports whether a request's accept_enc list names gzip.
func acceptsGzip(params map[string]any) bool {
	list, _ := params["accept_enc"].([]any)
	for _, v := range list {
		if s, _ := v.(string); s == EncGzip {
			return true
		}
	}
	return false
}

func decodeB64Param(params map[string]any, key string) ([]byte, error) {
	s, _ := params[key].(string)
	return base64.StdEncoding.DecodeString(s)
}

func intParam(params map[string]any, key string) (int, bool) {
	f, ok := toFloat(params[key])
	if !ok || f < 0 || f != float64(int(f)) {
		return 0, false
	}
	return int(f), true
}
