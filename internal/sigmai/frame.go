// Package sigmai implements the NextAuth "sigmai" transport: a protobuf-tagged
// frame carried over WebSocket, with X25519 key agreement and XChaCha20-Poly1305
// AEAD.
//
// Frame layout (recovered from 3UM @ 0x5ee4d8, encoder qkM @ 0x5ea1b4):
//
//	1  vKUB__       : varint   message type (33 == 0x21 outer header)
//	2  _2qUB        : bytes
//	3  _9qYB_____   : varint   header/version (vEM requires outer field 3 == 17)
//	4  n6YB__       : bytes
//	5  x6Q          : repeated message
//	6  (varint)
//	7  xqYB____     : bytes
//	8  xacB________ : bytes
//	9  kqUB_ / _1KYB____ : bytes
//	...
//	12 i6gB____________ : varint
//	13 p6gB_______________ / gIIB_________ : bytes
//	14 r6cB_______  : bytes
//	15 _7qYB_____   : bytes
//
// Fields are standard proto3 tags/varints; 2kM computes the size, 1UM writes.
package sigmai

import (
	"fmt"

	"kut-leuven-authenticator/internal/wire"
)

// Frame field numbers.
const (
	FType    = 1  // message type
	F2       = 2  //
	F3       = 3  // header/version (vEM checks == 17)
	F4       = 4  //
	F5       = 5  // repeated submessage
	F6       = 6  //
	F7       = 7  //
	F8       = 8  //
	F9       = 9  //
	F10      = 10 //
	F11      = 11 //
	F12      = 12 //
	F13      = 13 //
	F14      = 14 //
	F15      = 15 //
)

// TypeHeader is the frame type that triggers app dispatch (vEM/ykM).
const TypeHeader = 0x21 // 33

// Frame is a decoded sigmai frame.
type Frame struct {
	Type int    // field 1
	F2   []byte // field 2
	F3   int    // field 3
	F4   []byte // field 4
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

// NewTyped builds a frame with the given type, applying the fixed outer header
// (field 3 == 17) used by the sigmai envelope.
func NewTyped(typ int) *Frame {
	return &Frame{Type: typ, F3: 17}
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

// ErrWrongHeader is returned when a frame's outer header field is not 17.
var ErrWrongHeader = fmt.Errorf("sigmai: wrong header")
