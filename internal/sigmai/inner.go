package sigmai

import (
	"kut-leuven-authenticator/internal/wire"
)

// Inner is the message that is carried *inside* an encrypted frame.
//
// The native code encrypts/decrypts an `oUB` message (see _4UM @ 0x5f2438 for
// the writer and _3kM @ 0x5f0a30 for the reader) and the payload of a nested
// `4gB` message:
//
//	oUB
//	 1  repeated 4gB   (nested payload)
//	 2  bytes
//	 >=3 unrecognised bytes (native `gIIB_________`)
//
//	4gB
//	 1  varint
//	 2  bytes
//	 3  repeated bytes
//	 4  bytes
//	 >=5 unrecognised bytes
//
// A live server reply (type 17, sequence 1) decrypts to 68 bytes:
//
//	0a 42 1a 40 <64 bytes>
//
// i.e. one nested message (66 bytes) whose field 3 holds 64 bytes.
type Inner struct {
	// Nested holds the field 1 sub-messages.
	Nested []*Nested

	// Bytes is field 2.
	Bytes []byte

	// Unknown retains fields the native decoder dumps into its unrecognised
	// bucket, so re-encoding is lossless.
	Unknown []wire.Field
}

// Nested is the `4gB` sub-message carried in field 1 of an Inner.
type Nested struct {
	Varint   uint64   // field 1
	Bytes    []byte   // field 2
	Repeated [][]byte // field 3
	Bytes4   []byte   // field 4
	Unknown  []wire.Field
}

// ParseInner decodes a decrypted inner message.
func ParseInner(b []byte) (*Inner, error) {
	in := &Inner{}
	err := wire.Parse(b, func(f wire.Field) error {
		switch f.Num {
		case 1:
			n, err := ParseNested(f.Bytes)
			if err != nil {
				return err
			}
			in.Nested = append(in.Nested, n)
		case 2:
			in.Bytes = clone(f.Bytes)
		default:
			in.Unknown = append(in.Unknown, f)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return in, nil
}

// ParseNested decodes a `4gB` sub-message.
func ParseNested(b []byte) (*Nested, error) {
	n := &Nested{}
	err := wire.Parse(b, func(f wire.Field) error {
		switch f.Num {
		case 1:
			n.Varint = f.Varint
		case 2:
			n.Bytes = clone(f.Bytes)
		case 3:
			n.Repeated = append(n.Repeated, clone(f.Bytes))
		case 4:
			n.Bytes4 = clone(f.Bytes)
		default:
			n.Unknown = append(n.Unknown, f)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return n, nil
}

// Marshal serializes the inner message.
func (in *Inner) Marshal() []byte {
	var b []byte
	for _, n := range in.Nested {
		b = wire.AppendBytes(b, 1, n.Marshal())
	}
	if in.Bytes != nil {
		b = wire.AppendBytes(b, 2, in.Bytes)
	}
	for _, f := range in.Unknown {
		b = appendRawField(b, f)
	}
	return b
}

// Marshal serializes the nested sub-message.
func (n *Nested) Marshal() []byte {
	var b []byte
	if n.Varint != 0 {
		b = wire.AppendUvarintField(b, 1, n.Varint)
	}
	if n.Bytes != nil {
		b = wire.AppendBytes(b, 2, n.Bytes)
	}
	for _, v := range n.Repeated {
		b = wire.AppendBytes(b, 3, v)
	}
	if n.Bytes4 != nil {
		b = wire.AppendBytes(b, 4, n.Bytes4)
	}
	for _, f := range n.Unknown {
		b = appendRawField(b, f)
	}
	return b
}

// Payload returns the first 64-ish byte blob carried in the nested message's
// field 3, i.e. the application payload of the message.
func (in *Inner) Payload() []byte {
	for _, n := range in.Nested {
		for _, v := range n.Repeated {
			if len(v) > 0 {
				return v
			}
		}
		if len(n.Bytes4) > 0 {
			return n.Bytes4
		}
		if len(n.Bytes) > 0 {
			return n.Bytes
		}
	}
	return in.Bytes
}
