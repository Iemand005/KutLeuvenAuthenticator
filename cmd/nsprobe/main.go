// Command nsprobe performs the sigmai handshake against an arbitrary endpoint
// (default: the "ns" endpoint from a registration QR) and then dumps every
// subsequent frame, decrypted, with a recursive protobuf view.
//
// Usage:
//
//	nsprobe -qr "Registration code.png" [-url wss://...] [-wait 30s]
//	nsprobe -url wss://authenticator.icts.kuleuven.be/ns/sigmai
package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"kut-leuven-authenticator/internal/qr"
	"kut-leuven-authenticator/internal/session"
	"kut-leuven-authenticator/internal/sigmai"
	"kut-leuven-authenticator/internal/transport"
	"kut-leuven-authenticator/internal/wire"
)

func main() {
	qrPath := flag.String("qr", "", "registration QR PNG to read the endpoint from")
	url := flag.String("url", "wss://authenticator.icts.kuleuven.be/ns/sigmai", "endpoint")
	wait := flag.Duration("wait", 30*time.Second, "how long to listen after the handshake")
	sendMode := flag.String("send", "", "after the handshake send a message: 12309")
	mode := flag.String("mode", "", "reg: send the type-64 enrolment hello; auth: send a 12309 approval for a login QR")
	variant := flag.Int("variant", 1, "auth signing variant (1=structB, 2=4gB{12309,B}, 3=structA, 4=minimal B)")
	seed := flag.String("seed", "", "auth: comma-separated 32-byte hex Ed25519 seeds (default: random)")
	tsMode := flag.String("ts", "now", "auth timestamp source: now or qr")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	target := *url
	var reg *qr.Registration
	var login *qr.Login
	var qrPayload []byte
	if *qrPath != "" {
		codes, err := qr.DecodeFile(*qrPath)
		if err != nil {
			log.Fatalf("qr: %v", err)
		}
		qrPayload = codes[0].Payload
		log.Printf("QR %d bytes: %x", len(codes[0].Payload), codes[0].Payload)
		dump("qr", codes[0].Payload, 0)

		if l, err := qr.ParseLogin(qrPayload); err == nil && l.IsLogin() {
			login = l
			log.Printf("login QR: type=%d jacob=%d pac=%d ver=%d ts=%d (%s) nonce=%x",
				l.Type, l.Jacob, l.Pac, l.Version, l.Timestamp, l.Created().UTC(), l.Nonce)
			log.Printf("login QR: register=%s server=%s", l.RegisterID(), l.ServerID())
		} else {
			reg, err = qr.ParseRegistration(qrPayload)
			if err != nil {
				log.Fatalf("qr parse: %v", err)
			}
			log.Printf("registration: type=%d jacob=%d pac=%d ver=%d s6c=%d servers=%v",
				reg.Type, reg.Jacob, reg.Pac, reg.Version, reg.S6c, reg.Servers)
			if u := reg.ServerURL(); u != "" {
				log.Printf("QR server URL: %s", u)
				if *url == "wss://authenticator.icts.kuleuven.be/ns/sigmai" {
					target = u
				}
			}
		}
	}

	conn, err := transport.Dial(target, &transport.Config{HandshakeTimeout: 20 * time.Second})
	if err != nil {
		log.Fatalf("dial %s: %v", target, err)
	}
	defer conn.Close()
	log.Printf("connected %s (subprotocol=%q)", target, conn.Subprotocol())

	sess := session.New(conn)
	if *mode == "reg3" {
		if reg == nil {
			log.Fatalf("mode=%s needs -qr", *mode)
		}
		if _, err := sess.HandshakeWithTimeout(20 * time.Second); err != nil {
			log.Fatalf("handshake: %v", err)
		}
		hello := buildRegHello(reg, qrPayload)
		log.Printf("sending encrypted type-64 hello (%d B): %x", len(hello), hello)
		if err := sess.SendBytes(hello); err != nil {
			log.Fatalf("send: %v", err)
		}
		deadline := time.Now().Add(*wait)
		for {
			if err := conn.SetReadDeadline(deadline); err != nil {
				log.Fatalf("deadline: %v", err)
			}
			pt, err := sess.RecvPlaintext()
			if err != nil {
				log.Printf("recv: %v", err)
				return
			}
			log.Printf("=== plaintext (%d B): %x", len(pt), pt)
			dump("pt", pt, 0)
			explainRegReply(reg, pt)
		}
	}
	if *mode == "reg" || *mode == "reg2" {
		if reg == nil {
			log.Fatalf("mode=%s needs -qr", *mode)
		}
		if *mode == "reg2" {
			if _, err := sess.HandshakeWithTimeout(20 * time.Second); err != nil {
				log.Fatalf("handshake: %v", err)
			}
			log.Printf("handshake done; sending registration hello next")
		}
		hello := buildRegHello(reg, qrPayload)
		log.Printf("sending type-64 registration hello (%d B): %x", len(hello), hello)
		if err := conn.WriteBinary(hello); err != nil {
			log.Fatalf("send reg hello: %v", err)
		}
		deadline := time.Now().Add(*wait)
		for {
			if err := conn.SetReadDeadline(deadline); err != nil {
				log.Fatalf("deadline: %v", err)
			}
			_, raw, err := conn.ReadMessage()
			if err != nil {
				log.Printf("read: %v", err)
				return
			}
			log.Printf("=== raw frame (%d B): %x", len(raw), raw)
			dump("reply", raw, 0)
			explainRegReply(reg, raw)
		}
	}
	hs, err := sess.HandshakeWithTimeout(20 * time.Second)
	if err != nil {
		log.Fatalf("handshake: %v", err)
	}
	log.Printf("handshake OK seq=%d", hs.Sequence)
	log.Printf("plaintext(%d): %x", len(hs.Plaintext), hs.Plaintext)
	dump("hs", hs.Plaintext, 0)
	for _, n := range hs.Inner.Nested {
		if n.Varint == 12308 && len(n.Repeated) > 0 && len(n.Repeated[0]) == 64 {
			explain12308(reg, hs, n)
		}
	}

	if *mode == "auth" {
		if login == nil {
			log.Fatalf("mode=auth needs a login QR (-qr)")
		}
		if err := sendAuth(sess, hs, login, *variant, *seed, *tsMode == "qr"); err != nil {
			log.Fatalf("auth send: %v", err)
		}
	}

	if *sendMode != "" {
		if err := sendProbe(sess, hs, *sendMode); err != nil {
			log.Printf("send %s: %v", *sendMode, err)
		}
	}

	deadline := time.Now().Add(*wait)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			log.Fatalf("deadline: %v", err)
		}
		inner, err := sess.Recv()
		if err != nil {
			if time.Now().After(deadline) {
				log.Printf("done waiting")
				return
			}
			log.Printf("recv: %v", err)
			return
		}
		log.Printf("=== inner: %d nested, %d extra bytes ===", len(inner.Nested), len(inner.Bytes))
		for i, n := range inner.Nested {
			log.Printf("  nested[%d] varint=%d bytes=%x repeated=%x b4=%x unknown=%v",
				i, n.Varint, n.Bytes, n.Repeated, n.Bytes4, n.Unknown)
			if len(n.Bytes) > 0 {
				dump(fmt.Sprintf("nested[%d].f2", i), n.Bytes, 2)
			}
			for j, r := range n.Repeated {
				dump(fmt.Sprintf("nested[%d].f3[%d]", i, j), r, 2)
			}
			if n.Varint == 12308 && len(n.Repeated) > 0 && len(n.Repeated[0]) == 64 {
				explain12308(reg, hs, n)
			}
		}
		if len(inner.Bytes) > 0 {
			dump("inner.f2", inner.Bytes, 0)
		}
	}
}

// explain12308 tests the hypothesis that the server's type-12308 message
// carries a 64-byte Ed25519 signature over a session-bound message, using keys
// derived from the registration QR.
func explain12308(reg *qr.Registration, hs *session.HandshakeResult, n *sigmai.Nested) {
	if reg == nil {
		log.Printf("12308: no QR available; cannot test key candidates")
		return
	}
	fields, ok := parseAll(n.Bytes)
	if !ok || len(fields) == 0 || fields[0].Type != wire.TypeVarint {
		log.Printf("12308: cannot parse f2 payload: %x", n.Bytes)
		return
	}
	epoch := fields[0].Varint
	log.Printf("12308: f2 epoch=%d sig=%x", epoch, n.Repeated[0])
	log.Printf("12308: our ephemeral pub=%x", hs.EphemeralPub)
	log.Printf("12308: server pub=%x", hs.ServerPub)

	blobs := map[string][]byte{
		"w6cB": reg.W6c,
		"jaUB": reg.Ja,
		"oKcB": reg.OKc,
		"gaUB": reg.Ga,
	}
	keys := qrKeyCandidates(blobs)
	keys = append(keys, candidateKey{name: "serverPub", key: hs.ServerPub})
	var msgs []signedMessageCandidate
	pubs := []struct {
		name string
		val  []byte
	}{
		{"client", hs.EphemeralPub},
		{"server", hs.ServerPub},
	}
	for _, a := range pubs {
		for _, b := range pubs {
			if a.name == b.name {
				continue
			}
			msgs = append(msgs, signedMessageCandidates(12308, a.val, b.val, epoch)...)
		}
	}
	msgs = append(msgs, signedMessageCandidates(12308, hs.EphemeralPub, nil, epoch)...)
	hits := tryVerify(keys, msgs, n.Repeated[0])
	if len(hits) == 0 {
		log.Printf("12308: no QR-derived key verified the signature (%d keys x %d messages)", len(keys), len(msgs))
		return
	}
	for _, h := range hits {
		log.Printf("12308: MATCH %s", h)
	}
}

// dump prints a recursive protobuf interpretation. depth controls indentation
// only; every length-delimited field whose contents parse cleanly is expanded.
func dump(label string, b []byte, depth int) {
	indent := ""
	for i := 0; i < depth; i++ {
		indent += "  "
	}
	log.Printf("%s%s (%d B): %x", indent, label, len(b), b)
	fields, ok := parseAll(b)
	if !ok {
		return
	}
	for _, f := range fields {
		if f.Type == wire.TypeVarint {
			log.Printf("%s  f%d varint=%d (0x%x)", indent, f.Num, f.Varint, f.Varint)
			continue
		}
		if f.Type == wire.TypeBytes {
			if nested, ok := parseAll(f.Bytes); ok && len(f.Bytes) > 1 {
				dump(fmt.Sprintf("f%d", f.Num), f.Bytes, depth+1)
				_ = nested
			} else {
				log.Printf("%s  f%d bytes=%x %q", indent, f.Num, f.Bytes, printable(f.Bytes))
			}
		}
	}
}

func parseAll(b []byte) ([]wire.Field, bool) {
	var out []wire.Field
	if len(b) == 0 {
		return nil, false
	}
	err := wire.Parse(b, func(f wire.Field) error {
		out = append(out, f)
		return nil
	})
	return out, err == nil
}

func printable(b []byte) string {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return string(b)
}


