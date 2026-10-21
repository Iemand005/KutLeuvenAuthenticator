// Package sigmai implements the NextAuth "sigmai" transport: a protobuf-tagged
// frame carried over a WebSocket, with X25519 key agreement and XSalsa20-
// Poly1305 (NaCl secretbox) AEAD.
//
// # Outer frame
//
// The frame type is `qpwB_________________________4IB_________` (148 bytes on
// 32-bit ARM). The field numbers and wire types below were recovered from the
// generated encoder _1UM @ 0x5ec384 (and the size calculator _2kM), not
// guessed:
//
//	 1  vKUB__       varint   message type
//	 2  _2qUB        bytes
//	 3  _9qYB_____   varint   sequence number
//	 4  n6YB__       bytes    AEAD ciphertext (tag first)
//	 5  x6Q          bytes    repeated sub-message
//	 6  _9acB        varint
//	 7  xqYB____     bytes
//	 8  xacB________ bytes
//	 9  kqUB_        bytes
//	10  _1KYB____    bytes
//	12  i6gB         varint
//	13  p6gB         bytes
//	14  r6cB______   bytes
//	15  _7qYB_____   bytes
//
// Field 11 is never emitted by the encoder. Field 0 in the struct layout is
// the "unrecognised bytes" bucket (native `gIIB_________`).
//
// # Message types
//
//	16  client hello (unencrypted, carries our X25519 public key in field 2)
//	17  server hello reply (field 2 = server public key, field 3 = sequence
//	    number, field 4 = encrypted payload)
//	32  encrypted application frame (field 3 = sequence number, field 4 =
//	    encrypted inner message)
//	33  application dispatch trigger (yEM @ 0x5ebbec)
package sigmai

import (
	"fmt"

	"kut-leuven-authenticator/internal/wire"
)

// Frame field numbers.
const (
	FType  = 1  // message type
	F2     = 2  // bytes
	F3     = 3  // varint: sequence number
	F4     = 4  // bytes: ciphertext
	F5     = 5  // repeated sub-message
	F6     = 6  // varint
	F7     = 7  // bytes
	F8     = 8  // bytes
	F9     = 9  // bytes
	F10    = 10 // bytes
	F11    = 11 // bytes (not emitted by the native encoder)
	F12    = 12 // varint
	F13    = 13 // bytes
	F14    = 14 // bytes
	F15    = 15 // bytes
)

// Message types carried in frame field 1.
const (
	// TypeClientHello is the unencrypted first frame: field 2 = our public key.
	TypeClientHello = 16

	// TypeServerHello is the server's reply to the client hello. It carries
	// the server public key (field 2), the sequence number (field 3) and an
	// encrypted payload (field 4).
	TypeServerHello = 17

	// TypeEncrypted is an encrypted application frame. Field 3 holds the
	// sequence number and field 4 the encrypted inner message.
	TypeEncrypted = 32

	// TypeHeader is the frame type that triggers application dispatch
	// (yEM @ 0x5ebbec -> ykM @ 0x5ebd58).
	TypeHeader = 33
)

// Frame is a decoded sigmai frame.
type Frame struct {
	Type int    // field 1
	F2   []byte // field 2
	F3   int    // field 3: sequence number
	F4   []byte // field 4: ciphertext
	F5   [][]byte
	F6   int
	F7   []byte
	F8   []byte
	F9   []byte
	F10  []byte
	F11  []byte
	F12  int
	F13  []byte
	F14  []byte
	F15  []byte

	// Unknown retains unmodelled fields for lossless handling.
	Unknown []wire.Field
}

// ParseFrame decodes a sigmai frame.
func ParseFrame(b []byte) (*Frame, error) {
	f := &Frame{}
	err := wire.Parse(b, func(fl wire.Field) error {
		switch fl.Num {
		case FType:
			f.Type = int(fl.Varint)
		case F2:
			f.F2 = clone(fl.Bytes)
		case F3:
			f.F3 = int(fl.Varint)
		case F4:
			f.F4 = clone(fl.Bytes)
		case F5:
			f.F5 = append(f.F5, clone(fl.Bytes))
		case F6:
			f.F6 = int(fl.Varint)
		case F7:
			f.F7 = clone(fl.Bytes)
		case F8:
			f.F8 = clone(fl.Bytes)
		case F9:
			f.F9 = clone(fl.Bytes)
		case F10:
			f.F10 = clone(fl.Bytes)
		case F11:
			f.F11 = clone(fl.Bytes)
		case F12:
			f.F12 = int(fl.Varint)
		case F13:
			f.F13 = clone(fl.Bytes)
		case F14:
			f.F14 = clone(fl.Bytes)
		case F15:
			f.F15 = clone(fl.Bytes)
		default:
			f.Unknown = append(f.Unknown, fl)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Marshal serializes the frame with standard proto3 encoding, fields in
// ascending order.
func (f *Frame) Marshal() []byte {
	var b []byte
	if f.Type != 0 {
		b = wire.AppendUvarintField(b, FType, uint64(f.Type))
	}
	if f.F2 != nil {
		b = wire.AppendBytes(b, F2, f.F2)
	}
	if f.F3 != 0 {
		b = wire.AppendUvarintField(b, F3, uint64(f.F3))
	}
	if f.F4 != nil {
		b = wire.AppendBytes(b, F4, f.F4)
	}
	for _, v := range f.F5 {
		b = wire.AppendBytes(b, F5, v)
	}
	if f.F6 != 0 {
		b = wire.AppendUvarintField(b, F6, uint64(f.F6))
	}
	if f.F7 != nil {
		b = wire.AppendBytes(b, F7, f.F7)
	}
	if f.F8 != nil {
		b = wire.AppendBytes(b, F8, f.F8)
	}
	if f.F9 != nil {
		b = wire.AppendBytes(b, F9, f.F9)
	}
	if f.F10 != nil {
		b = wire.AppendBytes(b, F10, f.F10)
	}
	if f.F11 != nil {
		b = wire.AppendBytes(b, F11, f.F11)
	}
	if f.F12 != 0 {
		b = wire.AppendUvarintField(b, F12, uint64(f.F12))
	}
	if f.F13 != nil {
		b = wire.AppendBytes(b, F13, f.F13)
	}
	if f.F14 != nil {
		b = wire.AppendBytes(b, F14, f.F14)
	}
	if f.F15 != nil {
		b = wire.AppendBytes(b, F15, f.F15)
	}
	for _, fl := range f.Unknown {
		b = appendRawField(b, fl)
	}
	return b
}

// Sequence returns the frame's sequence number (field 3).
func (f *Frame) Sequence() uint64 { return uint64(f.F3) }

// NewEncryptedFrame wraps an encrypted inner message in the outbound frame
// envelope used by n0M @ 0x5e99b0: type 32, sequence in field 3, ciphertext in
// field 4.
func NewEncryptedFrame(seq uint64, ciphertext []byte) *Frame {
	return &Frame{Type: TypeEncrypted, F3: int(seq), F4: ciphertext}
}

// NewClientHello builds the unencrypted first frame (type 16) carrying our
// X25519 public key in field 2.
func NewClientHello(pub []byte) *Frame {
	return &Frame{Type: TypeClientHello, F2: pub}
}

func appendRawField(b []byte, fl wire.Field) []byte {
	switch fl.Type {
	case wire.TypeVarint:
		return wire.AppendUvarintField(b, fl.Num, fl.Varint)
	case wire.TypeBytes:
		return wire.AppendBytes(b, fl.Num, fl.Bytes)
	default:
		b = wire.AppendTag(b, fl.Num, fl.Type)
		return append(b, fl.Bytes...)
	}
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// ErrWrongHeader is returned when a frame's type is not the expected one.
var ErrWrongHeader = fmt.Errorf("sigmai: wrong header")
