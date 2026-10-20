// Command register opens the sigmai WebSocket for the application registration
// (enrolment) flow.
//
// It dials the mc channel, performs the sigmai handshake, and then drives the
// enrolment opcode sequence (TYPE_PROCESSOR_HEADLESS_REGISTER etc.). The exact
// registration message contents depend on the enrolment flow, which is still
// being reverse-engineered (see DOCUMENTATION.md §8); this command currently
// establishes the channel and prints the handshake material so it can be
// validated against a capture.
//
// Usage:
//
//	register [-channel mc|sfs] [-url wss://...] [-timeout 30s]
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"kut-leuven-authenticator/internal/config"
	"kut-leuven-authenticator/internal/session"
	"kut-leuven-authenticator/internal/transport"
)

func main() {
	channel := flag.String("channel", "mc", "sigmai channel: mc or sfs")
	url := flag.String("url", "", "override WebSocket URL")
	timeout := flag.Duration("timeout", 30*time.Second, "dial/handshake timeout")
	verbose := flag.Bool("v", true, "verbose output")
	flag.Parse()

	target := *url
	if target == "" {
		switch *channel {
		case "mc":
			target = config.KULeuven.MC.URL
		case "sfs":
			target = config.KULeuven.SFS.URL
		default:
			fmt.Fprintf(os.Stderr, "unknown channel %q (want mc or sfs)\n", *channel)
			os.Exit(2)
		}
	}

	log.SetFlags(0)
	if *verbose {
		log.Printf("dialing %s (channel=%s)", target, *channel)
	}

	conn, err := transport.Dial(target, &transport.Config{HandshakeTimeout: *timeout})
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	log.Printf("connected; negotiated subprotocol=%q", conn.Subprotocol())

	sess := session.New(conn)
	hs, err := sess.Handshake()
	if err != nil {
		log.Fatalf("handshake: %v", err)
	}

	log.Printf("handshake complete")
	log.Printf("  ephemeral pub : %x", hs.EphemeralPub)
	log.Printf("  server pub    : %x", hs.ServerPub)
	log.Printf("  key(initiator): %x", hs.KeyInitiator)
	log.Printf("  key(responder): %x", hs.KeyResponder)

	// TODO(enrolment): send TYPE_PROCESSOR_HEADLESS_REGISTER with the QR payload
	// material and drive TYPE_PROCESSOR_CONFIRM_NEW_ACCOUNT, then persist the
	// resulting account. See DOCUMENTATION.md §8 (open item: enrolment flow).
	log.Printf("channel established; enrolment message sequence pending RE (DOCUMENTATION.md §8)")
}
