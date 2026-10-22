// Package session implements a sigmai session: key agreement over a WebSocket
// and an encrypted frame channel.
//
// # Cryptography
//
//   - The session key is derived once, during the handshake, with
//     Crypto.DeriveKey: SHA-512(shared || client_pub || server_pub)[:32],
//     where shared is the X25519 ECDH secret.
//   - The AEAD is XSalsa20-Poly1305 in the NaCl "secretbox" layout (16-byte
//     Poly1305 tag first, no associated data).
//   - The 24-byte nonce is the frame sequence number in big-endian into the
//     first 4 bytes, the remaining 20 bytes zero (sigmai.NonceFromSeq).
//
// # Framing
//
// After the handshake, every message is an outer frame of type 32 whose field 3
// holds the sequence number and whose field 4 holds the encrypted inner
// message (see sigmai.NewEncryptedFrame and the native builder n0M @ 0x5e99b0).
//
// Sequence numbers are allocated by the native code in _4UM @ 0x5f2438:
//
//	v5 = tx + 2
//	role 0 (client): if v5 is odd -> v5 = tx + 3
//	role 1 (server): if v5 is even -> v5 = tx + 1
//
// The client (role 0) therefore always sends even sequence numbers, starting
// at 2, and only accepts odd, strictly increasing ones (native _4EM @ 0x5f21fc).
package session

import (
	"fmt"
	"sync"

	"kut-leuven-authenticator/internal/sigmai"
	"kut-leuven-authenticator/internal/transport"
)

// Role values used by the native key schedule and sequence allocator.
const (
	// RoleClient is the initiator (role 0): sends even sequence numbers.
	RoleClient byte = 0
	// RoleServer is the responder (role 1): sends odd sequence numbers.
	RoleServer byte = 1
)

// Session is an encrypted sigmai channel.
type Session struct {
	conn *transport.Conn

	key []byte

	// txSeq is the last sequence number we sent (always even for a client).
	txSeq uint64
	// rxSeq is the last sequence number we accepted (always odd for a client).
	rxSeq uint64

	mu sync.Mutex
}

// New creates an empty session bound to a connected WebSocket.
func New(conn *transport.Conn) *Session {
	return &Session{conn: conn}
}

// SetKey installs the session key.
func (s *Session) SetKey(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = append([]byte(nil), key...)
}

// Key returns the session key.
func (s *Session) Key() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.key...)
}

// NextTxSeq allocates the next send sequence number. A client always sends
// even sequence numbers (native _4UM @ 0x5f2438, role 0 branch).
func (s *Session) NextTxSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.txSeq + 2
	if seq&1 != 0 {
		seq = s.txSeq + 3
	}
	s.txSeq = seq
	return seq
}

// Send encrypts an inner message and writes it as a type-32 frame.
func (s *Session) Send(inner *sigmai.Inner) error {
	return s.SendBytes(inner.Marshal())
}

// SendBytes encrypts a raw plaintext and writes it as a type-32 frame.
func (s *Session) SendBytes(plaintext []byte) error {
	s.mu.Lock()
	key := append([]byte(nil), s.key...)
	s.mu.Unlock()
	if len(key) == 0 {
		return fmt.Errorf("sigmai: session key not established")
	}

	seq := s.NextTxSeq()
	ct, err := sigmai.Seal(key, sigmai.NonceFromSeq(seq), plaintext, nil)
	if err != nil {
		return err
	}
	return s.conn.WriteBinary(sigmai.NewEncryptedFrame(seq, ct).Marshal())
}

// RecvPlaintext reads one WebSocket message and returns the decrypted payload
// without assuming it is an inner oUB envelope. Sequence-number replay rules
// are enforced exactly as in Recv.
func (s *Session) RecvPlaintext() ([]byte, error) {
	_, raw, err := s.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	frame, err := sigmai.ParseFrame(raw)
	if err != nil {
		return nil, fmt.Errorf("sigmai: parse frame: %w", err)
	}
	switch frame.Type {
	case sigmai.TypeServerHello:
		return nil, fmt.Errorf("sigmai: unexpected server hello (sequence %d)", frame.Sequence())
	case sigmai.TypeEncrypted:
	default:
		return nil, fmt.Errorf("sigmai: unexpected frame type %d", frame.Type)
	}

	seq := frame.Sequence()
	s.mu.Lock()
	last := s.rxSeq
	s.mu.Unlock()
	if seq <= last {
		return nil, fmt.Errorf("sigmai: replayed sequence %d (last %d)", seq, last)
	}
	if seq&1 == 0 {
		return nil, fmt.Errorf("sigmai: sequence %d is not odd (client expects odd)", seq)
	}

	key := s.Key()
	pt, err := sigmai.Open(key, sigmai.NonceFromSeq(seq), frame.F4, nil)
	if err != nil {
		return nil, fmt.Errorf("sigmai: decrypt sequence %d: %w", seq, err)
	}

	s.mu.Lock()
	s.rxSeq = seq
	s.mu.Unlock()
	return pt, nil
}

// Recv reads one WebSocket message, decrypts it and returns the inner message.
// It enforces the native replay rules: the sequence number must be strictly
// greater than the last accepted one and, for a client, odd.
func (s *Session) Recv() (*sigmai.Inner, error) {
	_, raw, err := s.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	frame, err := sigmai.ParseFrame(raw)
	if err != nil {
		return nil, fmt.Errorf("sigmai: parse frame: %w", err)
	}
	switch frame.Type {
	case sigmai.TypeServerHello:
		return nil, fmt.Errorf("sigmai: unexpected server hello (sequence %d)", frame.Sequence())
	case sigmai.TypeEncrypted:
	default:
		return nil, fmt.Errorf("sigmai: unexpected frame type %d", frame.Type)
	}

	seq := frame.Sequence()
	s.mu.Lock()
	last := s.rxSeq
	s.mu.Unlock()
	if seq <= last {
		return nil, fmt.Errorf("sigmai: replayed sequence %d (last %d)", seq, last)
	}
	if seq&1 == 0 {
		return nil, fmt.Errorf("sigmai: sequence %d is not odd (client expects odd)", seq)
	}

	key := s.Key()
	pt, err := sigmai.Open(key, sigmai.NonceFromSeq(seq), frame.F4, nil)
	if err != nil {
		return nil, fmt.Errorf("sigmai: decrypt sequence %d: %w", seq, err)
	}

	s.mu.Lock()
	s.rxSeq = seq
	s.mu.Unlock()

	return sigmai.ParseInner(pt)
}
