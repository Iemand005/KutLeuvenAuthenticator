// Command hs performs the live sigmai handshake against the real server and
// prints everything the handshake produces:
//
//  1. dials the endpoint,
//  2. sends the unencrypted type-16 client hello (field 2 = our X25519
//     public key),
//  3. reads the type-17 server reply (field 2 = server public key, field 3 =
//     sequence number, field 4 = encrypted payload),
//  4. derives the session key (SHA-512(shared || client_pub || server_pub)
//     [:32], role 0) and opens field 4 with XSalsa20-Poly1305 using the
//     big-endian sequence number as the nonce,
//  5. decodes the decrypted inner message.
//
// Usage:
//
//	hs [-channel mc|sfs] [-url wss://...] [-wait 20s]
package main

import (
	"flag"
	"log"
	"time"

	"kut-leuven-authenticator/internal/config"
	"kut-leuven-authenticator/internal/session"
	"kut-leuven-authenticator/internal/sigmai"
	"kut-leuven-authenticator/internal/transport"
)

func main() {
	channel := flag.String("channel", "mc", "sigmai channel")
	url := flag.String("url", "", "override WebSocket URL")
	wait := flag.Duration("wait", 20*time.Second, "handshake timeout")
	flag.Parse()

	target := *url
	if target == "" {
		switch *channel {
		case "mc":
			target = config.KULeuven.MC.URL
		case "sfs":
			target = config.KULeuven.SFS.URL
		default:
			log.Fatalf("unknown channel %q", *channel)
		}
	}
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	conn, err := transport.Dial(target, &transport.Config{HandshakeTimeout: 20 * time.Second})
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	log.Printf("connected %s (subprotocol=%q)", target, conn.Subprotocol())

	sess := session.New(conn)
	hs, err := sess.HandshakeWithTimeout(*wait)
	if err != nil {
		log.Fatalf("handshake: %v", err)
	}

	log.Printf("handshake OK")
	log.Printf("  client pub  : %x", hs.EphemeralPub)
	log.Printf("  server pub  : %x", hs.ServerPub)
	log.Printf("  session key : %x", hs.Key)
	log.Printf("  sequence    : %d", hs.Sequence)
	log.Printf("  plaintext   : %x", hs.Plaintext)
	log.Printf("  payload(%d) : %x", len(hs.Inner.Payload()), hs.Inner.Payload())
	if p := hs.Inner.Payload(); len(p) > 0 {
		log.Printf("  payload ascii: %q", p)
	}
}

var _ = sigmai.TypeEncrypted
