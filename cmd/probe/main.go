// Command probe dials a sigmai endpoint, logs the WebSocket upgrade in detail,
// then (optionally) sends candidate handshake frames and logs every byte the
// server returns. It is the live-instrumentation tool used to converge the
// handshake against the real server.
//
// Usage:
//
//	probe [-channel mc|sfs] [-url wss://...] [-send hex|empty|typed33] [-wait 10s]
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"kut-leuven-authenticator/internal/config"
	"kut-leuven-authenticator/internal/sigmai"
	"kut-leuven-authenticator/internal/transport"

	"github.com/gorilla/websocket"
)

func main() {
	channel := flag.String("channel", "mc", "sigmai channel: mc or sfs")
	url := flag.String("url", "", "override WebSocket URL")
	send := flag.String("send", "none", "payload to send after connect: none|typed33|<hex>")
	subproto := flag.String("subproto", "", "Sec-WebSocket-Protocol value")
	wait := flag.Duration("wait", 12*time.Second, "how long to read server frames")
	flag.Parse()

	target := *url
	if target == "" {
		switch *channel {
		case "mc":
			target = config.KULeuven.MC.URL
		case "sfs":
			target = config.KULeuven.SFS.URL
		default:
			fmt.Fprintf(os.Stderr, "unknown channel %q\n", *channel)
			os.Exit(2)
		}
	}

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Printf("target = %s", target)

	cfg := &transport.Config{HandshakeTimeout: 20 * time.Second}
	if *subproto != "" {
		cfg.Subprotocols = []string{*subproto}
	}

	conn, resp, err := transport.DialRaw(target, cfg)
	logUpgrade(resp)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	log.Printf("connected; negotiated subprotocol=%q", conn.Subprotocol())

	// Send an optional payload.
	switch {
	case *send == "none":
	case *send == "empty":
		log.Printf("sending zero-length binary frame")
		if err := conn.WriteBinary(nil); err != nil {
			log.Fatalf("write: %v", err)
		}
	case *send == "typed33":
		f := &sigmai.Frame{Type: sigmai.TypeHeader}
		b := f.Marshal()
		log.Printf("sending typed33 frame (%d bytes): %x", len(b), b)
		if err := conn.WriteBinary(b); err != nil {
			log.Fatalf("write: %v", err)
		}
	default:
		b, err := hex.DecodeString(*send)
		if err != nil {
			log.Fatalf("bad -send hex: %v", err)
		}
		log.Printf("sending %d raw bytes: %x", len(b), b)
		if err := conn.WriteBinary(b); err != nil {
			log.Fatalf("write: %v", err)
		}
	}

	// Read frames until the deadline.
	deadline := time.Now().Add(*wait)
	_ = conn.SetReadDeadline(deadline)
	for {
		typ, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err) {
				log.Printf("read: unexpected close: %v", err)
			} else {
				log.Printf("read ended: %v", err)
			}
			return
		}
		kind := "binary"
		if typ == websocket.TextMessage {
			kind = "text"
		}
		log.Printf("<< %s frame, %d bytes: %x", kind, len(data), data)
		if typ == websocket.TextMessage {
			log.Printf("   as text: %q", string(data))
		}
	}
}

func logUpgrade(resp *http.Response) {
	if resp == nil {
		log.Printf("no HTTP upgrade response captured")
		return
	}
	log.Printf("HTTP %d %s", resp.StatusCode, resp.Status)
	for k, v := range resp.Header {
		log.Printf("  hdr %s: %v", k, v)
	}
}
