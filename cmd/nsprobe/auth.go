package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"kut-leuven-authenticator/internal/qr"
	"kut-leuven-authenticator/internal/session"
	"kut-leuven-authenticator/internal/sigmai"
	"kut-leuven-authenticator/internal/wire"
)

// authKeys holds the two Ed25519 signers used by the approval message. The
// native code (y0U @ 0x609974) asks each signer for its public key (the
// itab->_2Hg_.len slot) and then asks it to Sign(ctx, msg) (the .cap slot).
type authKeys struct {
	pub1, pub2 []byte
	priv1      ed25519.PrivateKey
	priv2      ed25519.PrivateKey
}

// parseSeeds accepts one or two comma-separated 32-byte hex seeds. When no
// seeds are given, two random keypairs are generated.
func parseSeeds(s string) (*authKeys, error) {
	var seeds [][]byte
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		b, err := hex.DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("seed %q: %w", part, err)
		}
		if len(b) != ed25519.SeedSize {
			return nil, fmt.Errorf("seed %q is %d bytes, want %d", part, len(b), ed25519.SeedSize)
		}
		seeds = append(seeds, b)
	}
	for len(seeds) < 2 {
		b := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		seeds = append(seeds, b)
	}
	k := &authKeys{}
	k.priv1 = ed25519.NewKeyFromSeed(seeds[0])
	k.priv2 = ed25519.NewKeyFromSeed(seeds[1])
	k.pub1 = append([]byte(nil), k.priv1.Public().(ed25519.PublicKey)...)
	k.pub2 = append([]byte(nil), k.priv2.Public().(ed25519.PublicKey)...)
	return k, nil
}

// buildStructB mirrors the 80-byte skA encoding used for the approval's f2:
//
//	f1 0x0A bytes  signer2 public key
//	f2 0x12 bytes  signer1 public key
//	f3 0x1A bytes  QR f6 (register id)      // 5MB.mmg
//	f4 0x22 bytes  QR f7 (server id)        // 4Hg.wqYB
//	f5 0x28 uint64 timestamp (Unix ns)      // 4Xg.h2
//	f6 0x32 bytes  QR f13 nonce             // 4Xg.wYIB
func buildStructB(login *qr.Login, k *authKeys, ts uint64, nonce []byte) []byte {
	var b []byte
	b = wire.AppendBytes(b, 1, k.pub2)
	b = wire.AppendBytes(b, 2, k.pub1)
	b = wire.AppendBytes(b, 3, login.Register)
	if len(login.Server) > 0 {
		b = wire.AppendBytes(b, 4, login.Server)
	}
	b = wire.AppendUvarintField(b, 5, ts)
	if len(nonce) > 0 {
		b = wire.AppendBytes(b, 6, nonce)
	}
	return b
}

// handshakeChallenge extracts the server's 12308 challenge (its timestamp is
// carried in f2.f1 and its 64-byte signature in f3).
func handshakeChallenge(hs *session.HandshakeResult) (epoch uint64, sig []byte, ok bool) {
	if hs == nil || hs.Inner == nil {
		return 0, nil, false
	}
	for _, n := range hs.Inner.Nested {
		if n.Varint != 12308 {
			continue
		}
		wire.Parse(n.Bytes, func(f wire.Field) error {
			if f.Num == 1 {
				epoch = f.Varint
			}
			return nil
		})
		if len(n.Repeated) > 0 {
			sig = n.Repeated[0]
		}
		return epoch, sig, true
	}
	return 0, nil, false
}

// buildStructA mirrors the sEA/tEA payload that both signers sign in y0U:
// field 1 is the message type, field 2 is the struct-B blob, field 4 is the
// timestamp. Remaining fields are left at their proto3 defaults.
func buildStructA(structB []byte, ts uint64) []byte {
	var b []byte
	b = wire.AppendUvarintField(b, 1, 12309)
	b = wire.AppendBytes(b, 2, structB)
	b = wire.AppendUvarintField(b, 4, ts)
	return b
}

// sendAuth builds and sends the 12309 approval for a login QR.
//
// The envelope (4gB) is:
//
//	f1 varint   12309
//	f2 bytes    skA(struct B)
//	f3 repeated signatures over tEA(struct A)
func sendAuth(sess *session.Session, hs *session.HandshakeResult, login *qr.Login, variant int, seedSpec string, useQRTime bool) error {
	k, err := parseSeeds(seedSpec)
	if err != nil {
		return err
	}

	ts := uint64(time.Now().UnixNano())
	if useQRTime {
		ts = login.Timestamp
	}
	nonce := login.Nonce
	epoch, challengeSig, haveChallenge := handshakeChallenge(hs)

	structB := buildStructB(login, k, ts, nonce)
	structA := buildStructA(structB, ts)

	var msg []byte
	switch variant {
	case 1:
		msg = structB
	case 2:
		msg = marshal4G(nil, 12309, structB, nil, nil)
	case 3:
		msg = structA
	case 4:
		msg = buildStructB(&qr.Login{Register: login.Register}, k, ts, nil)
	case 5:
		if !haveChallenge {
			return fmt.Errorf("variant 5 needs a 12308 challenge")
		}
		structB = buildStructB(login, k, epoch, challengeSig)
		msg = structB
		ts = epoch
	case 6:
		if !haveChallenge {
			return fmt.Errorf("variant 6 needs a 12308 challenge")
		}
		structB = buildStructB(login, k, epoch, nonce)
		structA = buildStructA(structB, epoch)
		msg = structA
		ts = epoch
	case 7:
		if !haveChallenge {
			return fmt.Errorf("variant 7 needs a 12308 challenge")
		}
		structB = buildStructB(login, k, epoch, challengeSig)
		msg = marshal4G(nil, 12309, structB, nil, nil)
		ts = epoch
	default:
		return fmt.Errorf("unknown auth variant %d", variant)
	}

	sig1 := ed25519.Sign(k.priv1, msg)
	sig2 := ed25519.Sign(k.priv2, msg)

	n := &sigmai.Nested{
		Varint:   12309,
		Bytes:    structB,
		Repeated: [][]byte{sig1, sig2},
	}
	inner := &sigmai.Inner{Nested: []*sigmai.Nested{n}}

	log.Printf("auth variant=%d ts=%d (qr ts %d)", variant, ts, login.Timestamp)
	log.Printf("  register=%s server=%s nonce=%x", login.RegisterID(), login.ServerID(), login.Nonce)
	log.Printf("  structB(%d)=%x", len(structB), structB)
	log.Printf("  signed msg(%d)=%x", len(msg), msg)
	log.Printf("  sig1=%x", sig1)
	log.Printf("  sig2=%x", sig2)
	log.Printf("  inner(%d)=%x", len(inner.Marshal()), inner.Marshal())

	return sess.Send(inner)
}
