// Package transport dials the sigmai WebSocket endpoints.
//
// The native app uses a gorilla/websocket-style dialer (iUQ @ 0x5f4f90) and
// validates the scheme == "wss" (iUU @ 0x603224). TLS uses pinned HARICA roots
// (HARICA TLS ECC Root CA 2021 + HARICA TLS RSA Root CA 2021), which are
// *public* trust anchors, so the system root pool already contains them. Pinning
// is offered as an opt-in via Config.RootCAs.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

// Config configures a dial.
type Config struct {
	// RootCAs, if non-nil, restricts TLS verification to these roots (pinning).
	// Leave nil to use the system root pool.
	RootCAs *x509.CertPool

	// TLSConfig, if non-nil, is used verbatim (overrides RootCAs).
	TLSConfig *tls.Config

	// Headers are extra handshake headers (e.g. authorisation, subprotocol).
	Headers http.Header

	// Subprotocols advertised via Sec-WebSocket-Protocol.
	Subprotocols []string

	HandshakeTimeout time.Duration
}

// Conn wraps a gorilla websocket connection.
type Conn struct {
	*websocket.Conn

	// Handshake records the HTTP upgrade response, if captured.
	Handshake *http.Response
}

var defaultDialer = websocket.Dialer{
	HandshakeTimeout: 30 * time.Second,
	ReadBufferSize:   1 << 16,
	WriteBufferSize:  1 << 16,
}

// Dial opens a sigmai WebSocket connection to rawURL (must be wss://...).
func Dial(rawURL string, cfg *Config) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("transport: malformed ws or wss URL: %w", err)
	}
	if u.Scheme != "wss" {
		return nil, fmt.Errorf("transport: scheme must be wss, got %q", u.Scheme)
	}

	d := defaultDialer
	if cfg != nil {
		if cfg.RootCAs != nil || cfg.TLSConfig != nil {
			tc := cfg.TLSConfig
			if tc == nil {
				tc = &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12}
			}
			d.TLSClientConfig = tc
		}
		if cfg.HandshakeTimeout > 0 {
			d.HandshakeTimeout = cfg.HandshakeTimeout
		}
		if cfg.Subprotocols != nil {
			d.Subprotocols = cfg.Subprotocols
		}
	}

	var hdr http.Header
	if cfg != nil {
		hdr = cfg.Headers
	}
	c, resp, err := d.Dial(rawURL, hdr)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("transport: websocket: bad handshake (HTTP %d): %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("transport: dial: %w", err)
	}
	return &Conn{Conn: c, Handshake: resp}, nil
}

// DialRaw opens a WebSocket, returning the upgrade response even on failure, so
// callers can inspect the server's HTTP status and headers.
func DialRaw(rawURL string, cfg *Config) (*Conn, *http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: malformed ws or wss URL: %w", err)
	}
	if u.Scheme != "wss" {
		return nil, nil, fmt.Errorf("transport: scheme must be wss, got %q", u.Scheme)
	}
	d := defaultDialer
	if cfg != nil {
		if cfg.RootCAs != nil || cfg.TLSConfig != nil {
			tc := cfg.TLSConfig
			if tc == nil {
				tc = &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12}
			}
			d.TLSClientConfig = tc
		}
		if cfg.HandshakeTimeout > 0 {
			d.HandshakeTimeout = cfg.HandshakeTimeout
		}
		if cfg.Subprotocols != nil {
			d.Subprotocols = cfg.Subprotocols
		}
	}
	var hdr http.Header
	if cfg != nil {
		hdr = cfg.Headers
	}
	c, resp, err := d.Dial(rawURL, hdr)
	if err != nil {
		return nil, resp, err
	}
	return &Conn{Conn: c, Handshake: resp}, resp, nil
}

// ReadMessage reads the next binary/text message payload.
func (c *Conn) ReadMessage() (int, []byte, error) {
	typ, data, err := c.Conn.ReadMessage()
	return typ, data, err
}

// WriteBinary sends a binary frame (sigmai frames are binary).
func (c *Conn) WriteBinary(data []byte) error {
	return c.Conn.WriteMessage(websocket.BinaryMessage, data)
}

// SetReadDeadline / SetWriteDeadline are inherited from websocket.Conn.
