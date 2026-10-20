// Package session implements a sigmai session: key agreement over a WebSocket
// and authenticated frame exchange.
//
// Frame cryptography:
//   - each direction has its own 32-byte session key, derived via Crypto.DeriveKey
//     (X25519 + HMAC-SHA256 salt + SHA-512 expand; see sigmai.Crypto).
//   - the AEAD is XChaCha20-Poly1305 with a 24-byte nonce derived from the frame
//     sequence number (sigmai.NonceFromSeq), not carried on the wire.
//   - the receiver enforces monotonically increasing sequence numbers (replay
//     protection; native 4EM @ 0x5f21fc).
//
// NOTE: the exact handshake message sequence (which frame first carries the
// ephemeral public key, and the pj8 role flag) is not yet byte-verified; see
// DOCUMENTATION.md §8. PerformHandshake is the single place to finalise once a
// capture is available.
package session

import (
	"encoding/binary"
	"fmt"
	"sync"

	"kut-leuven-authenticator/internal/sigmai"
	"kut-leuven-authenticator/internal/transport"
)

// Session is an authenticated sigmai channel.
type Session struct {
	conn *transport.Conn

	sendKey []byte
	recvKey []byte

	sendSeq uint64
	recvSeq uint64

	mu sync.Mutex
}

// New creates an empty session bound to a connected WebSocket.
func New(conn *transport.Conn) *Session {
	return &Session{conn: conn}
}

// SendKey / RecvKey install the directional session keys (from the handshake).
func (s *Session) SetKeys(send, recv []byte) {
	s.sendKey = send
	s.recvKey = recv
}

// SendFrame encrypts and writes a frame, using the next send sequence number.
func (s *Session) SendFrame(f *sigmai.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	seq := s.sendSeq
	s.sendSeq++

	plaintext := f.Marshal()
	nonce := sigmai.NonceFromSeq(seq)
	ct, err := sigmai.Seal(s.sendKey, nonce, plaintext, nil)
	if err != nil {
		return err
	}

	wire := encodeEnvelope(seq, ct)
	return s.conn.WriteBinary(wire)
}

// RecvFrame reads one WebSocket message, decrypts it, and returns the frame.
// It enforces a strictly increasing receive sequence number.
func (s *Session) RecvFrame() (*sigmai.Frame, error) {
	_, raw, err := s.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	seq, ct, err := decodeEnvelope(raw)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if seq <= s.recvSeq && s.recvSeq != 0 {
		s.mu.Unlock()
		return nil, fmt.Errorf("sigmai: replayed sequence %d (last %d)", seq, s.recvSeq)
	}
	s.recvSeq = seq
	s.mu.Unlock()

	nonce := sigmai.NonceFromSeq(seq)
	pt, err := sigmai.Open(s.recvKey, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	return sigmai.ParseFrame(pt)
}

// encodeEnvelope wraps a sequence number and ciphertext into the on-wire
// container. The native framing places the sequence number alongside the
// ciphertext; the precise byte layout is finalised with a capture (see §8).
//
// Layout used here: [8-byte little-endian seq][ciphertext||tag].
func encodeEnvelope(seq uint64, ct []byte) []byte {
	out := make([]byte, 8+len(ct))
	binary.LittleEndian.PutUint64(out[:8], seq)
	copy(out[8:], ct)
	return out
}

func decodeEnvelope(raw []byte) (uint64, []byte, error) {
	if len(raw) < 8 {
		return 0, nil, fmt.Errorf("sigmai: frame too short (%d bytes)", len(raw))
	}
	seq := binary.LittleEndian.Uint64(raw[:8])
	return seq, raw[8:], nil
}
