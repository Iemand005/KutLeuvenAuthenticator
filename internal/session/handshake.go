package session

import (
	"fmt"
	"time"

	"kut-leuven-authenticator/internal/sigmai"
)

// Handshake drives the sigmai key agreement over an open WebSocket.
//
// The native flow (mEM @ 0x5e9270 -> uUM @ 0x5ead2c -> vEM @ 0x5eb0f8) is:
//
//  1. generate an ephemeral X25519 keypair (pD8),
//  2. send an unencrypted type-16 frame whose field 2 is our public key
//     (vUM @ 0x5eb3f8),
//  3. receive the type-17 reply: field 2 = server public key, field 3 =
//     sequence number, field 4 = encrypted payload,
//  4. derive the session key with role 0 (client) and open field 4 with the
//     nonce derived from the sequence number.
func (s *Session) Handshake() (*HandshakeResult, error) {
	return s.HandshakeWithTimeout(20 * time.Second)
}

// HandshakeWithTimeout is Handshake with an explicit read deadline.
func (s *Session) HandshakeWithTimeout(timeout time.Duration) (*HandshakeResult, error) {
	priv, err := sigmai.NewKeyPair()
	if err != nil {
		return nil, err
	}
	// Role 0 = client: the key block is shared || client_pub || server_pub.
	priv.SetRole(RoleClient)

	hello := sigmai.NewClientHello(priv.PublicKey())
	if err := s.conn.WriteBinary(hello.Marshal()); err != nil {
		return nil, fmt.Errorf("sigmai: send client hello: %w", err)
	}

	deadline := time.Now().Add(timeout)
	for {
		if err := s.conn.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		_, raw, err := s.conn.ReadMessage()
		if err != nil {
			return nil, fmt.Errorf("sigmai: read server hello: %w", err)
		}
		reply, err := sigmai.ParseFrame(raw)
		if err != nil {
			return nil, fmt.Errorf("sigmai: parse server hello: %w", err)
		}
		if reply.Type != sigmai.TypeServerHello {
			// The native code ignores frames that are not the hello reply.
			continue
		}

		serverPub := reply.F2
		if len(serverPub) != 32 {
			return nil, fmt.Errorf("sigmai: server public key is %d bytes, want 32", len(serverPub))
		}

		key, err := priv.DeriveKey(serverPub)
		if err != nil {
			return nil, err
		}

		seq := reply.Sequence()
		plaintext, err := sigmai.Open(key, sigmai.NonceFromSeq(seq), reply.F4, nil)
		if err != nil {
			return nil, fmt.Errorf("sigmai: open server hello payload: %w", err)
		}

		inner, err := sigmai.ParseInner(plaintext)
		if err != nil {
			return nil, fmt.Errorf("sigmai: parse server hello payload: %w", err)
		}

		s.SetKey(key)
		s.mu.Lock()
		s.rxSeq = seq
		s.mu.Unlock()

		return &HandshakeResult{
			EphemeralPub: priv.PublicKey(),
			ServerPub:    serverPub,
			Key:          key,
			Sequence:     seq,
			Plaintext:    plaintext,
			Inner:        inner,
		}, nil
	}
}

// HandshakeResult exposes handshake values for debugging/validation.
type HandshakeResult struct {
	EphemeralPub []byte
	ServerPub    []byte
	Key          []byte
	Sequence     uint64
	Plaintext    []byte
	Inner        *sigmai.Inner
}
