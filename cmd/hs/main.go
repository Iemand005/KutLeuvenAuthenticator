// Command hs performs the live sigmai handshake against the real server:
// it sends a type-16 frame carrying an ephemeral X25519 public key, reads the
// type-17 server reply, and then attempts to derive the session key and decrypt
// the server's encrypted payload (field 4) under several documented pj8
// variants. It prints every candidate so the correct schedule can be identified.
//
// Usage:
//
//	hs [-channel mc|sfs] [-role 0|1] [-seed priv|pub|zero|shared] [-wait 6s]
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"time"

	"kut-leuven-authenticator/internal/config"
	"kut-leuven-authenticator/internal/sigmai"
	"kut-leuven-authenticator/internal/transport"
	"kut-leuven-authenticator/internal/wire"
)

func main() {
	channel := flag.String("channel", "mc", "sigmai channel")
	url := flag.String("url", "", "override WebSocket URL")
	wait := flag.Duration("wait", 6*time.Second, "read timeout")
	flag.Parse()

	target := *url
	if target == "" {
		switch *channel {
		case "mc":
			target = config.KULeuven.MC.URL
		case "sfs":
			target = config.KULeuven.SFS.URL
		}
	}
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	conn, err := transport.Dial(target, &transport.Config{HandshakeTimeout: 20 * time.Second})
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	log.Printf("connected %s", target)

	// Ephemeral keypair.
	priv, err := sigmai.NewKeyPair()
	if err != nil {
		log.Fatalf("keypair: %v", err)
	}
	pub := priv.PublicKey()
	hello := &sigmai.Frame{Type: 16, F2: pub}
	hb := hello.Marshal()
	log.Printf("-> type16 f2=%x (%d bytes): %x", pub, len(hb), hb)
	if err := conn.WriteBinary(hb); err != nil {
		log.Fatalf("write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(*wait))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		log.Fatalf("read: %v", err)
	}
	log.Printf("<- %d bytes: %x", len(raw), raw)

	reply, err := sigmai.ParseFrame(raw)
	if err != nil {
		log.Fatalf("parse reply: %v", err)
	}
	log.Printf("reply type=%d f2=%x f3=%d f4len=%d f10=%x",
		reply.Type, reply.F2, reply.F3, len(reply.F4), reply.F10)

	if len(reply.F2) != 32 {
		log.Fatalf("server pubkey len = %d, want 32", len(reply.F2))
	}
	serverPub := reply.F2
	shared, err := priv.SharedSecret(serverPub)
	if err != nil {
		log.Fatalf("shared: %v", err)
	}
	log.Printf("X25519 shared = %x", shared)

	ct := reply.F4
	if len(ct) < 16 {
		log.Printf("field4 too short for AEAD tag")
		return
	}

	// Try documented pj8 schedule variants for the key, then decrypt field 4
	// under both nonce guesses (seq 0, all-zero) and additional-data guesses.
	privBytes := priv.PrivateKeyBytes()
	seeds := map[string][]byte{
		"priv32":  privBytes,
		"pub32":   pub,
		"srvPub":  serverPub,
		"shared":  shared,
		"zero":    make([]byte, 32),
	}
	roles := map[string]byte{"init(1)": 1, "resp(0)": 0}
	nonces := map[string][]byte{
		"seq0":  sigmai.NonceFromSeq(0),
		"zero":  make([]byte, 24),
	}

	for sname, seed := range seeds {
		for rname, role := range roles {
			key := pj8(privBytes, serverPub, shared, seed, role)
			log.Printf("key[seed=%s role=%s] = %x", sname, rname, key)
			for nname, nonce := range nonces {
				pt, err := sigmai.Open(key[:], nonce, ct, nil)
				if err == nil {
					log.Printf("  *** DECRYPT OK [%s/%s/%s]: %x (%q)", sname, rname, nname, pt, string(pt))
				}
			}
		}
	}
	log.Printf("done; raw field4 = %x", ct)
	_ = rand.Reader
	_ = sha512.Sum512
	_ = wire.TypeVarint
	_ = fmt.Sprintf
	_ = hex.EncodeToString
}

// pj8 implements the native key schedule with configurable salt source so we can
// identify the correct variant empirically.
func pj8(priv, peerPub, shared, seed []byte, role byte) []byte {
	if len(seed) < 32 {
		seed = append(seed, make([]byte, 32-len(seed))...)
	}
	salt := hmacSha256(seed[:32], seed[:32])
	block := make([]byte, 0, 64)
	if role != 0 {
		block = append(block, shared...)
		block = append(block, salt...)
	} else {
		block = append(block, salt...)
		block = append(block, shared...)
	}
	sum := sha512.Sum512(block)
	return sum[:32]
}

func hmacSha256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
