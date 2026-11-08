package ws

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/websocket"
)

func TestWebSocketProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://secure-proxy.test:8080")
	t.Setenv("HTTP_PROXY", "http://plain-proxy.test:8080")
	t.Setenv("NO_PROXY", "bypass.test")
	for _, tc := range []struct{ endpoint, want string }{
		{"wss://hub.test/ws", "secure-proxy.test:8080"},
		{"ws://hub.test/ws", "plain-proxy.test:8080"},
		{"wss://bypass.test/ws", ""},
	} {
		u, _ := url.Parse(tc.endpoint)
		proxy, err := webSocketProxy(u)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if proxy != nil {
			got = proxy.Host
		}
		if got != tc.want {
			t.Errorf("%s: proxy = %q, want %q", tc.endpoint, got, tc.want)
		}
	}
}

func TestWebSocketThroughProxy(t *testing.T) {
	t.Run("http", func(t *testing.T) {
		hub := httptest.NewTLSServer(websocket.Handler(func(ws *websocket.Conn) {
			defer ws.Close()
			var data []byte
			if err := websocket.Message.Receive(ws, &data); err == nil {
				_ = websocket.Message.Send(ws, data)
			}
		}))
		defer hub.Close()
		auth := make(chan string, 1)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect || r.Host != strings.TrimPrefix(hub.URL, "https://") {
				http.Error(w, "unexpected request", 400)
				return
			}
			auth <- r.Header.Get("Proxy-Authorization")
			upstream, err := net.Dial("tcp", r.Host)
			if err != nil {
				http.Error(w, "upstream unavailable", 502)
				return
			}
			defer upstream.Close()
			client, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer client.Close()
			_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			_ = buffer.Flush()
			go func() { _, _ = io.Copy(upstream, buffer); _ = upstream.Close() }()
			_, _ = io.Copy(client, upstream)
		})
		proxy := httptest.NewServer(handler)
		defer proxy.Close()
		proxyURL, _ := url.Parse(proxy.URL)
		proxyURL.User = url.UserPassword("user", "password")
		cfg, _ := websocket.NewConfig("wss"+strings.TrimPrefix(hub.URL, "https")+"/ws?token=private", hub.URL)
		roots := x509.NewCertPool()
		roots.AddCert(hub.Certificate())
		cfg.TlsConfig = &tls.Config{RootCAs: roots}
		ws, err := dialWebSocketConfig(cfg, proxyURL)
		if err != nil {
			t.Fatal(err)
		}
		defer ws.Close()
		if err := websocket.Message.Send(ws, []byte("hello")); err != nil {
			t.Fatal(err)
		}
		var got []byte
		if err := websocket.Message.Receive(ws, &got); err != nil {
			t.Fatal(err)
		}
		if string(got) != "hello" {
			t.Fatalf("unexpected echo %q", got)
		}
		if got := <-auth; got != "Basic dXNlcjpwYXNzd29yZA==" {
			t.Fatalf("proxy auth = %q", got)
		}
	})
}

func TestProxyRejectionDoesNotExposeSecrets(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "private-token", http.StatusForbidden) }))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	cfg, _ := websocket.NewConfig("wss://hub.test/ws?token=private-token", "https://hub.test")
	_, err := dialWebSocketConfig(cfg, proxyURL)
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "private-token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProxyDoesNotDisableTLSVerification(t *testing.T) {
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted proxy must fail before CONNECT") }))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	cfg, _ := websocket.NewConfig("wss://hub.test/ws?token=private-token", "https://hub.test")
	if _, err := dialWebSocketConfig(cfg, proxyURL); err == nil {
		t.Fatal("untrusted HTTPS proxy accepted")
	}
}
