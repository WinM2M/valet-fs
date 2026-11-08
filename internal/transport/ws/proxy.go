package ws

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/websocket"
)

// dialWebSocket follows the same proxy environment as the hub's HTTP requests.
// Mapping ws(s) to http(s) makes HTTPS_PROXY, HTTP_PROXY and NO_PROXY apply.
func dialWebSocket(endpoint, origin string) (*websocket.Conn, error) {
	cfg, err := websocket.NewConfig(endpoint, origin)
	if err != nil {
		return nil, fmt.Errorf("invalid WebSocket configuration")
	}
	proxyURL, err := webSocketProxy(cfg.Location)
	if err != nil {
		return nil, fmt.Errorf("WebSocket proxy configuration is invalid")
	}
	return dialWebSocketConfig(cfg, proxyURL)
}

func webSocketProxy(location *url.URL) (*url.URL, error) {
	proxyTarget := *location
	if proxyTarget.Scheme == "wss" {
		proxyTarget.Scheme = "https"
	} else {
		proxyTarget.Scheme = "http"
	}
	return http.ProxyFromEnvironment(&http.Request{URL: &proxyTarget})
}

func dialWebSocketConfig(cfg *websocket.Config, proxyURL *url.URL) (*websocket.Conn, error) {
	const timeout = 30 * time.Second
	if proxyURL == nil {
		cfg.Dialer = &net.Dialer{Timeout: timeout}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		conn, err := cfg.DialContext(ctx)
		if dialErr, ok := err.(*websocket.DialError); ok {
			// DialError includes the session token from the WebSocket URL.
			return nil, fmt.Errorf("WebSocket connection: %w", dialErr.Err)
		}
		return conn, err
	}
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported WebSocket proxy scheme %q", proxyURL.Scheme)
	}
	target := cfg.Location.Host
	if cfg.Location.Port() == "" {
		port := "80"
		if cfg.Location.Scheme == "wss" {
			port = "443"
		}
		target = net.JoinHostPort(cfg.Location.Hostname(), port)
	}
	proxyAddr := proxyURL.Host
	if proxyURL.Port() == "" {
		port := "80"
		if proxyURL.Scheme == "https" {
			port = "443"
		}
		proxyAddr = net.JoinHostPort(proxyURL.Hostname(), port)
	}
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to WebSocket proxy: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if proxyURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: proxyURL.Hostname()})
		conn = tlsConn
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("WebSocket proxy TLS: %w", err)
		}
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		credentials := proxyURL.User.Username() + ":" + password
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("WebSocket proxy CONNECT: %w", err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, fmt.Errorf("WebSocket proxy response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		// Do not include the response body, proxy credentials, or session URL.
		return nil, fmt.Errorf("WebSocket proxy CONNECT rejected: HTTP %d", response.StatusCode)
	}
	conn = &bufferedConn{Conn: conn, reader: reader}
	if cfg.Location.Scheme == "wss" {
		tlsConfig := cfg.TlsConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = cfg.Location.Hostname()
		}
		tlsConn := tls.Client(conn, tlsConfig)
		conn = tlsConn
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("WebSocket TLS: %w", err)
		}
	}
	ws, err := websocket.NewClient(cfg, conn)
	if err != nil {
		return nil, fmt.Errorf("WebSocket handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	ok = true
	return ws, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
