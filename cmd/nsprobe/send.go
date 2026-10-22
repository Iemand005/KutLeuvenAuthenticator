package main

import (
	"crypto/ed25519"
	"fmt"

	"kut-leuven-authenticator/internal/session"
	"kut-leuven-authenticator/internal/sigmai"
	"kut-leuven-authenticator/internal/wire"
)

// sendProbe sends a hand-built probe message in the given mode and returns.
func sendProbe(sess *session.Session, hs *session.HandshakeResult, mode string) error {
	switch mode {
	case "12309":
		env := []byte{}
		env = wire.AppendUvarintField(env, 1, 12309)
		env = wire.AppendBytes(env, 2, hs.EphemeralPub)
		env = wire.AppendBytes(env, 3, hs.ServerPub)

		seed := make([]byte, ed25519.SeedSize)
		priv := ed25519.NewKeyFromSeed(seed)
		sig := ed25519.Sign(priv, env)

		n := &sigmai.Nested{Varint: 12309, Bytes: env, Repeated: [][]byte{sig}}
		inner := &sigmai.Inner{Nested: []*sigmai.Nested{n}}
		fmt.Printf("send 12309 env=%x sig=%x\n", env, sig)
		return sess.Send(inner)
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
}
