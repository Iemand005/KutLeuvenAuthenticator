// Command hsx performs a live sigmai handshake against the real endpoint:
//
//  1. dials, sends a type-16 frame with field 2 = our X25519 public key
//  2. reads the server's type-17 reply (field 2 = server pub, field 4 = ciphertext)
//  3. brute-forces the pj8 key schedule (all 96-byte block arrangements and
//     several derivations), nonce layouts and tag placements against field 4,
//     printing any candidate that authenticates.
//
// It is the live oracle used to converge the exact crypto until the server's
// payload decrypts, after which the same routines are wired into the session.
package main

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"log"
	"sort"
	"time"

	"golang.org/x/crypto/nacl/secretbox"

	"kut-leuven-authenticator/internal/config"
	"kut-leuven-authenticator/internal/sigmai"
	"kut-leuven-authenticator/internal/transport"
)

func main() {
	channel := flag.String("channel", "mc", "sigmai channel: mc or sfs")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	target := config.KULeuven.MC.URL
	if *channel == "sfs" {
		target = config.KULeuven.SFS.URL
	}
	conn, err := transport.Dial(target, &transport.Config{HandshakeTimeout: 20 * time.Second})
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	kp, err := sigmai.NewKeyPair()
	if err != nil {
		log.Fatalf("keypair: %v", err)
	}
	pub := kp.PublicKey()
	priv := kp.PrivateKeyBytes()
	log.Printf("client priv=%x", priv)
	log.Printf("client pub =%x", pub)

	fr := &sigmai.Frame{Type: 16, F2: pub}
	if err := conn.WriteBinary(fr.Marshal()); err != nil {
		log.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		log.Fatalf("read: %v", err)
	}
	log.Printf("<< %d bytes: %x", len(raw), raw)
	reply, err := sigmai.ParseFrame(raw)
	if err != nil {
		log.Fatalf("parse: %v", err)
	}
	log.Printf("reply type=%d f2=%x f3=%d f4(%d)=%x f10=%x", reply.Type, reply.F2, reply.F3, len(reply.F4), reply.F4, reply.F10)

	serverPub := reply.F2
	ct := reply.F4
	if len(serverPub) != 32 {
		log.Fatalf("server pub is %d bytes, expected 32", len(serverPub))
	}

	// Shared secret from our private and the server public.
	cr, _ := sigmai.NewKeyPairFromSeed(priv)
	shared, err := cr.SharedSecret(serverPub)
	if err != nil {
		log.Fatalf("shared: %v", err)
	}
	log.Printf("shared=%x", shared)

	baseShared := x25519Base(shared)
	partset := map[string][]byte{
		"shared":   shared,
		"pub":      pub,
		"srv":      serverPub,
		"priv":     priv,
		"bSh":      baseShared,
		"sha256sh": sha256sum(shared),
	}
	// In case pj8's scalar is not the private key we think it is, add DH
	// variants where the scalar is the public key, or the server pub, etc.
	if shPub, err := ecdhShared(pub, serverPub); err == nil {
		partset["shPub"] = shPub
	}
	if shSrv, err := ecdhShared(serverPub, pub); err == nil {
		partset["shSrv"] = shSrv
	}
	if bSh, err := ecdhShared(shared, serverPub); err == nil {
		partset["shBSh"] = bSh
	}

	names := make([]string, 0, len(partset))
	for k := range partset {
		names = append(names, k)
	}
	sort.Strings(names)

	// Nonce candidates for seq (reply.F3).
	seq := uint64(reply.F3)
	nonces := map[string][]byte{}
	nonces["le32_front"] = leNonce(seq, 4, false, false)
	nonces["le64_front"] = leNonce(seq, 8, false, false)
	nonces["be32_front"] = leNonce(seq, 4, true, false)
	nonces["le32_back"] = leNonce(seq, 4, false, true)
	nonces["zero24"] = make([]byte, 24)

	tryKey := func(name string, key []byte) {
		for nn, nonce := range nonces {
			tryOpenX(name, nn, key, nonce, ct)
		}
	}

	// 1/2/3-part arrangements, SHA-512[:32] and SHA-256.
	for _, a := range names {
		tryKey("sha512("+a+")[:32]", sha512sum(partset[a])[:32])
		tryKey("sha256("+a+")", sha256sum(partset[a]))
	}
	for _, a := range names {
		for _, b := range names {
			tryKey("sha512("+a+"|"+b+")[:32]", sha512sum(cat(partset[a], partset[b]))[:32])
			for _, c := range names {
				if a == b || b == c || a == c {
					continue
				}
				tryKey("sha512("+a+"|"+b+"|"+c+")[:32]", sha512sum(cat(partset[a], partset[b], partset[c]))[:32])
			}
		}
	}
	log.Printf("brute force complete")
}

func tryOpenX(name, nn string, key, nonce, ct []byte) {
	if len(ct) < 16 {
		return
	}
	var k [32]byte
	copy(k[:], key)
	var n [24]byte
	copy(n[:], nonce)
	if pt, ok := secretbox.Open(nil, ct, &n, &k); ok {
		log.Printf("*** HIT key=%s nonce=%s pt(%d)=%x %q", name, nn, len(pt), pt, string(pt))
	}
}

func leNonce(seq uint64, w int, be, back bool) []byte {
	n := make([]byte, 24)
	off := 0
	if back {
		off = 24 - w
	}
	for i := 0; i < w; i++ {
		b := byte(seq >> (8 * i))
		if be {
			n[off+w-1-i] = b
		} else {
			n[off+i] = b
		}
	}
	return n
}

func x25519Base(scalar []byte) []byte {
	pk, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil
	}
	return pk.PublicKey().Bytes()
}

func ecdhShared(scalar, peer []byte) ([]byte, error) {
	pr, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	pk, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return pr.ECDH(pk)
}

func cat(bs ...[]byte) []byte {
	var o []byte
	for _, b := range bs {
		o = append(o, b...)
	}
	return o
}
func sha256sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
func sha512sum(b []byte) []byte { s := sha512.Sum512(b); return s[:] }
