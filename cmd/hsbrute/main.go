// Command hsbrute captures a real sigmai handshake, then brute-forces the pj8
// key schedule offline against the server's encrypted field-4 payload. It tries
// many block compositions / hash functions / AEAD variants / nonces / ADs and
// prints any that decrypt successfully, identifying the exact schedule.
//
// Usage:
//
//	hsbrute [-channel mc|sfs] [-capture file]
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"kut-leuven-authenticator/internal/config"
	"kut-leuven-authenticator/internal/sigmai"
	"kut-leuven-authenticator/internal/transport"
)

type capture struct {
	Priv      string `json:"priv"`
	Pub       string `json:"pub"`
	ServerPub string `json:"server_pub"`
	Field4    string `json:"field4"`
	Field10   string `json:"field10"`
	F3        int    `json:"f3"`
}

func main() {
	channel := flag.String("channel", "mc", "sigmai channel")
	captureFile := flag.String("capture", "", "read a saved capture instead of dialing")
	flag.Parse()
	log.SetFlags(log.Ltime)

	var cap capture
	if *captureFile != "" {
		b, err := os.ReadFile(*captureFile)
		if err != nil {
			log.Fatalf("read capture: %v", err)
		}
		if err := json.Unmarshal(b, &cap); err != nil {
			log.Fatalf("parse capture: %v", err)
		}
	} else {
		target := config.KULeuven.MC.URL
		if *channel == "sfs" {
			target = config.KULeuven.SFS.URL
		}
		conn, err := transport.Dial(target, &transport.Config{HandshakeTimeout: 20 * time.Second})
		if err != nil {
			log.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		priv, err := sigmai.NewKeyPair()
		if err != nil {
			log.Fatalf("keypair: %v", err)
		}
		pub := priv.PublicKey()
		if err := conn.WriteBinary((&sigmai.Frame{Type: 16, F2: pub}).Marshal()); err != nil {
			log.Fatalf("write: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			log.Fatalf("read: %v", err)
		}
		reply, err := sigmai.ParseFrame(raw)
		if err != nil {
			log.Fatalf("parse: %v", err)
		}
		cap = capture{
			Priv: hex.EncodeToString(priv.PrivateKeyBytes()), Pub: hex.EncodeToString(pub),
			ServerPub: hex.EncodeToString(reply.F2), Field4: hex.EncodeToString(reply.F4),
			Field10: hex.EncodeToString(reply.F10), F3: reply.F3,
		}
		out, _ := json.MarshalIndent(cap, "", "  ")
		os.WriteFile("capture.json", out, 0o644)
		log.Printf("saved capture.json")
	}

	priv, _ := hex.DecodeString(cap.Priv)
	serverPub, _ := hex.DecodeString(cap.ServerPub)
	ct, _ := hex.DecodeString(cap.Field4)
	f10, _ := hex.DecodeString(cap.Field10)
	pub, _ := hex.DecodeString(cap.Pub)

	cr, _ := sigmai.NewKeyPairFromSeed(priv)
	shared, _ := cr.SharedSecret(serverPub)
	log.Printf("shared=%x", shared)
	log.Printf("ct(%d)=%x", len(ct), ct)

	// Candidate 32-byte keys.
	keys := map[string][]byte{
		"raw-shared":   shared,
		"sha256-sh":    sha256sum(shared),
		"sha512-sh32":  sha512sum(shared)[:32],
		"priv32":       priv,
		"sha256-priv":  sha256sum(priv),
		"sha256-srv":   sha256sum(serverPub),
		"sha256-pub":   sha256sum(pub),
		"hmac-priv":    hmacf(priv, priv),
		"hmac-shared":  hmacf(shared, shared),
	}
	// pj8-style derived keys: SHA-512(block)[:32] for many block orders (2 and 3 parts).
	parts := map[string][]byte{
		"shared": shared, "priv": priv, "srv": serverPub, "pub": pub,
		"salt": hmacf(priv, priv), "salt2": hmacf(priv, priv),
		"saltSh": hmacf(shared, shared),
	}
	for pn, p := range parts {
		keys["sha512("+pn+")"] = sha512sum(p)[:32]
		keys["hmac(priv,"+pn+")"] = hmacf(priv, p)
		keys["hmac("+pn+",priv)"] = hmacf(p, priv)
	}
	// 2-part and 3-part concatenations.
	names := []string{"shared", "priv", "srv", "pub", "salt", "saltSh"}
	for _, a := range names {
		for _, b := range names {
			keys["sha512("+a+"|"+b+")"] = sha512sum(concat(parts[a], parts[b]))[:32]
			for _, c := range names {
				keys["sha512("+a+"|"+b+"|"+c+")"] = sha512sum(concat(parts[a], parts[b], parts[c]))[:32]
			}
		}
	}
	log.Printf("candidate keys: %d", len(keys))

	// AEAD variants: full field4 as ct+tag with external nonce; or 12-byte nonce prefix.
	nonceSet := map[string][]byte{
		"zero24": make([]byte, 24), "zero12": make([]byte, 12),
		"srv-nonce?" : make([]byte, 24),
	}
	ads := map[string][]byte{"nil": nil, "f10": f10, "srv": serverPub}

	hits := 0
	for kn, key := range keys {
		for nname, nonce := range nonceSet {
			for aname, ad := range ads {
				// XChaCha20-Poly1305, ct = field4
				tryOpen(kn, nname, aname, key, nonce, ct, ad, func(pt []byte) {
					log.Printf("*** X OK key=%s nonce=%s ad=%s pt=%x %q", kn, nname, aname, pt, string(pt))
					hits++
				})
			}
		}
		// IETF ChaCha20-Poly1305: nonce = ct[:12], body = ct[12:]
		if len(ct) > 12 {
			tryOpenIETF(kn, key, ct[:12], ct[12:], nil, func(pt []byte) {
				log.Printf("*** IETF OK key=%s nonce=ct[:12] pt=%x %q", kn, pt, string(pt))
				hits++
			})
		}
		// 24-byte nonce prefix variant
		if len(ct) > 24 {
			tryOpen(kn, "ct[:24]", "nil", key, ct[:24], ct[24:], nil, func(pt []byte) {
				log.Printf("*** X(nonce=ct[:24]) OK key=%s pt=%x %q", kn, pt, string(pt))
				hits++
			})
		}
	}
	log.Printf("done, %d hits", hits)
}

func tryOpen(kn, nname, aname string, key, nonce, ct, ad []byte, ok func([]byte)) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return
	}
	if pt, err := aead.Open(nil, nonce, ct, ad); err == nil {
		ok(pt)
	}
}

func tryOpenIETF(kn string, key, nonce, ct, ad []byte, ok func([]byte)) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return
	}
	if pt, err := aead.Open(nil, nonce, ct, ad); err == nil {
		ok(pt)
	}
}

func concat(bs ...[]byte) []byte {
	var o []byte
	for _, b := range bs {
		o = append(o, b...)
	}
	return o
}
func sha256sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
func sha512sum(b []byte) []byte { s := sha512.Sum512(b); return s[:] }
func hmacf(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

var _ = fmt.Sprintf
