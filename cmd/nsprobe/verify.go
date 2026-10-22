package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"kut-leuven-authenticator/internal/wire"
)

// candidateKey is a named 32-byte Ed25519 public key guess.
type candidateKey struct {
	name string
	key  []byte
}

// qrKeyCandidates derives 32-byte public-key candidates from the 16-byte
// blobs carried in the registration QR.
func qrKeyCandidates(blobs map[string][]byte) []candidateKey {
	order := []string{"w6cB", "jaUB", "oKcB", "gaUB"}
	var out []candidateKey
	for i := 0; i < len(order); i++ {
		for j := 0; j < len(order); j++ {
			a, b := blobs[order[i]], blobs[order[j]]
			if len(a) != 16 || len(b) != 16 {
				continue
			}
			k := make([]byte, 32)
			copy(k, a)
			copy(k[16:], b)
			name := order[i] + "||" + order[j]
			out = append(out, candidateKey{name: name, key: k})
			s := sha256.Sum256(k)
			out = append(out, candidateKey{name: "sha256(" + name + ")", key: s[:]})
			for _, part := range [][]byte{a, b} {
				h := sha256.Sum256(part)
				out = append(out, candidateKey{name: "sha256(" + name + " part)", key: h[:]})
			}
		}
	}
	out = append(out, configKeyCandidates()...)
	return out
}

// configKeyCandidates returns the 32-byte keys embedded in the app's
// nextauth.json (sfs/mc service keys and both halves of field 100).
func configKeyCandidates() []candidateKey {
	hexKeys := []struct{ name, hex string }{
		{"cfg.sfs.f2", "03b67efde8dda50f02edcba4eaf93ab42e6f590d2d1503b03cabc7cc92e8e0ab"},
		{"cfg.mc.f2", "ad6181665d9894b6c42296dde81c9b935206f854c96d0d896f36f8760fa2a131"},
		{"cfg.mc.f3", "6852f60b9107da8aaddbb3264c7bc7bc84ff1832d451b0cc6b8f1cd2add9f347"},
		{"cfg.f100.lo", "d3bc94f0a577058c5b9106464807f9207409db948df7dfba197955bf5ab5d7b9"},
		{"cfg.f100.hi", "c768dc8e0420f6e63785b10a8423e871e8746c934245ba1dd9ade7084cdb110c"},
	}
	var out []candidateKey
	for _, hk := range hexKeys {
		b, err := hex.DecodeString(hk.hex)
		if err != nil || len(b) != 32 {
			continue
		}
		out = append(out, candidateKey{name: hk.name, key: b})
	}
	return out
}

// signedMessageCandidate encodes a plausible pre-image of the server's 12308
// signature using the same field order as the native marshaler sUA.
type signedMessageCandidate struct {
	name string
	msg  []byte
}

// signedMessageCandidates encodes plausible pre-images of the server's 12308
// signature. The native marshaler (sUA) emits fields in ascending order.
func signedMessageCandidates(typ uint64, pub, pub2 []byte, epoch uint64) []signedMessageCandidate {
	var out []signedMessageCandidate
	add := func(name string, b []byte) {
		out = append(out, signedMessageCandidate{name: name, msg: b})
	}
	enc := func(parts [][2]int) []byte {
		var m []byte
		for _, p := range parts {
			switch p[0] {
			case 1:
				if typ != 0 {
					m = wire.AppendUvarintField(m, 1, typ)
				}
			case 2:
				if len(pub) > 0 {
					m = wire.AppendBytes(m, 2, pub)
				}
			case 3:
				if len(pub2) > 0 {
					m = wire.AppendBytes(m, 3, pub2)
				}
			case 4:
				if epoch != 0 {
					m = wire.AppendUvarintField(m, 4, epoch)
				}
			}
		}
		return m
	}
	add("1,2,3,4", enc([][2]int{{1, 0}, {2, 0}, {3, 0}, {4, 0}}))
	add("1,2,3", enc([][2]int{{1, 0}, {2, 0}, {3, 0}}))
	add("1,2,4", enc([][2]int{{1, 0}, {2, 0}, {4, 0}}))
	add("2,3,4", enc([][2]int{{2, 0}, {3, 0}, {4, 0}}))
	add("1,2", enc([][2]int{{1, 0}, {2, 0}}))
	add("1,3,4", enc([][2]int{{1, 0}, {3, 0}, {4, 0}}))
	add("2,4", enc([][2]int{{2, 0}, {4, 0}}))

	var eb [8]byte
	binary.LittleEndian.PutUint64(eb[:], epoch)
	var m []byte
	if typ != 0 {
		m = wire.AppendUvarintField(m, 1, typ)
	}
	if len(pub) > 0 {
		m = wire.AppendBytes(m, 2, pub)
	}
	if len(pub2) > 0 {
		m = wire.AppendBytes(m, 3, pub2)
	}
	m = wire.AppendBytes(m, 4, eb[:])
	add("1,2,3,4bytes8le", m)

	return out
}

// tryVerify reports every (key, message) pair for which sig is a valid
// Ed25519 signature.
func tryVerify(keys []candidateKey, msgs []signedMessageCandidate, sig []byte) []string {
	var hits []string
	if len(sig) != ed25519.SignatureSize {
		return hits
	}
	for _, k := range keys {
		if len(k.key) != ed25519.PublicKeySize {
			continue
		}
		for _, m := range msgs {
			if ed25519.Verify(ed25519.PublicKey(k.key), m.msg, sig) {
				hits = append(hits, fmt.Sprintf("key=%s msg=%s", k.name, m.name))
			}
		}
	}
	return hits
}
