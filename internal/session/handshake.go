package session

import (
	"crypto/rand"
	"fmt"

	"kut-leuven-authenticator/internal/sigmai"
)

// Handshake drives the sigmai key agreement after the WebSocket is open.
//
// The cryptographic primitives and the pj8 key schedule are known
// (sigmai.Crypto), but the exact message order and the role flag are not yet
// byte-verified against a live server (DOCUMENTATION.md §8). This implementation
// follows the most likely shape:
//
//  1. generate an ephemeral X25519 keypair,
//  2. send our public key in a typed frame (TypeHeader),
//  3. receive the server's public key,
//  4. derive send/recv keys via DeriveKey with role = initiator.
//
// When a real capture is available, adjust the field carrying the public key
// (here F2) and the role flag.
func (s *Session) Handshake() (*HandshakeResult, error) {
	priv, err := sigmai.NewKeyPair()
	if err != nil {
		return nil, err
	}
	priv.SetRole(1) // initiator

	// 1+2: send our ephemeral public key (field 2) and a KDF seed (field 4).
	seed, err := RandomNonce(32)
	if err != nil {
		return nil, err
	}
	hello := sigmai.NewTyped(sigmai.TypeHeader)
	hello.F2 = priv.PublicKey()
	hello.F4 = seed
	if err := s.conn.WriteBinary(hello.Marshal()); err != nil {
		return nil, fmt.Errorf("sigmai: send hello: %w", err)
	}

	// 3: receive the server's public key.
	_, raw, err := s.conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("sigmai: read server key: %w", err)
	}
	peer, err := sigmai.ParseFrame(raw)
	if err != nil {
		return nil, fmt.Errorf("sigmai: parse server key frame: %w", err)
	}
	peerPub := peer.F2
	if len(peerPub) != 32 {
		return nil, fmt.Errorf("sigmai: server public key not 32 bytes (field 2 len=%d)", len(peerPub))
	}

	// 4: derive directional keys. The pj8 salt source is not yet byte-verified,
	// so we seed both sides with a 32-byte value exchanged in the hello frame
	// (field 4) and derive both role orderings for validation.
	keyA, err := priv.DeriveKey(peerPub, seed)
	if err != nil {
		return nil, err
	}

	// The responder-order key (role=0) is derived from a fresh schedule.
	resp := *priv
	resp.SetRole(0)
	keyB, err := resp.DeriveKey(peerPub, seed)
	if err != nil {
		return nil, err
	}

	// Default: send=A (initiator), recv=B. Adjust once verified.
	s.SetKeys(keyA, keyB)

	return &HandshakeResult{
		EphemeralPub: priv.PublicKey(),
		ServerPub:    peerPub,
		Seed:         seed,
		KeyInitiator: keyA,
		KeyResponder: keyB,
	}, nil
}

// HandshakeResult exposes handshake values for debugging/validation.
type HandshakeResult struct {
	EphemeralPub []byte
	ServerPub    []byte
	Seed         []byte
	KeyInitiator []byte
	KeyResponder []byte
}

// RandomNonce returns n random bytes (helper for nonces/salts).
func RandomNonce(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
