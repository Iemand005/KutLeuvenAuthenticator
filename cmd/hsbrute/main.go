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
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
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
	pub, _ := hex.DecodeString(cap.Pub)
	seq := uint64(cap.F3)

	cr, _ := sigmai.NewKeyPairFromSeed(priv)
	shared, _ := cr.SharedSecret(serverPub)
	log.Printf("shared=%x", shared)
	log.Printf("ct(%d)=%x", len(ct), ct)
	log.Printf("seq=%d", seq)

	// --- Exhaustive pj8 block search: SHA-512(perm of 3 parts)[:32],
	// plus SHA-256, plus 2-part variants. Parts include raw shared, pubkeys,
	// the base-mult of priv (== pub), the base-mult of shared, and priv. ---
	baseOfShared, _ := x25519Base(shared)
	baseOfPriv, _ := x25519Base(priv)
	partset := map[string][]byte{
		"shared":   shared,
		"pub":      pub,
		"srv":      serverPub,
		"priv":     priv,
		"bSh":      baseOfShared, // X25519_base(shared)
		"bPriv":    baseOfPriv,   // == pub
		"sha256sh": sha256sum(shared),
	}
	// Nonce candidates (all 24 bytes unless noted).
	nonces := map[string][]byte{}
	mkFront := func(w int, be bool) []byte {
		n := make([]byte, 24)
		for i := 0; i < w; i++ {
			if be {
				n[w-1-i] = byte(seq >> (8 * i))
			} else {
				n[i] = byte(seq >> (8 * i))
			}
		}
		return n
	}
	nonces["le64_front"] = mkFront(8, false)
	nonces["be64_front"] = mkFront(8, true)
	nonces["le32_front"] = mkFront(4, false)
	nonces["be32_front"] = mkFront(4, true)
	nonces["le16_front"] = mkFront(2, false)
	nonces["zero24"] = make([]byte, 24)

	pkeys, pnames := []string{}, []string{}
	for k := range partset {
		pnames = append(pnames, k)
	}
	sort.Strings(pnames)
	// all ordered triples (with repetition) of distinct part names
	for _, a := range pnames {
		for _, b := range pnames {
			for _, c := range pnames {
				if a == b || b == c || a == c {
					continue
				}
				pkeys = append(pkeys, a+"|"+b+"|"+c)
			}
		}
	}
	log.Printf("ordered triples: %d", len(pkeys))

	hits := 0
	tryKey := func(kname string, key []byte) {
		for nname, nonce := range nonces {
			tryOpen(kname, nname, "nil", key, nonce, ct, nil, func(pt []byte) {
				log.Printf("*** X OK key=%s nonce=%s pt(%d)=%x %q", kname, nname, len(pt), pt, string(pt))
				hits++
			})
		}
	}
	for _, t := range pkeys {
		parts := strings.Split(t, "|")
		block := concat(partset[parts[0]], partset[parts[1]], partset[parts[2]])
		tryKey("sha512("+t+")[:32]", sha512sum(block)[:32])
	}
	// 2-part and single-part for good measure
	for _, a := range pnames {
		tryKey("sha512("+a+")[:32]", sha512sum(partset[a])[:32])
		for _, b := range pnames {
			tryKey("sha512("+a+"|"+b+")[:32]", sha512sum(concat(partset[a], partset[b]))[:32])
			tryKey("sha256("+a+"|"+b+")", sha256sum(concat(partset[a], partset[b])))
		}
	}
	log.Printf("exhaustive block search done, %d hits", hits)
	if hits > 0 {
		return
	}
	log.Printf("no hits; primary key was sha512(shared|pub|srv)[:32]")
}

func tryOpen(kn, nname, aname string, key, nonce, ct, ad []byte, ok func([]byte)) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return
	}
	// Native lays the 16-byte Poly1305 tag FIRST (oz8 reads ct[16:] as the
	// ciphertext and ct[:16] as the tag). Go's AEAD expects tag-suffix, so
	// reorder before opening.
	reordered := append(append([]byte{}, ct[16:]...), ct[:16]...)
	if pt, err := aead.Open(nil, nonce, reordered, ad); err == nil {
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

// x25519Base computes X25519_base(scalar) = the public key for a private scalar
// (mirrors hj8 @ 0x5a7b24).
func x25519Base(scalar []byte) ([]byte, error) {
	pk, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	return pk.PublicKey().Bytes(), nil
}

var _ = fmt.Sprintf
