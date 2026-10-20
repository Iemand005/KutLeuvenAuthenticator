// Package wire implements the plain proto3 wire format used by the NextAuth
// inner protocol (the `gi3` envelope) and by the sigmai frame.
//
// All integers are standard base-128 little-endian varints, tags are
// (field_number << 3) | wire_type, and length-delimited fields are prefixed by
// a varint length. No delta or ZigZag transform is applied.
package wire

import (
	"errors"
	"fmt"
)

// Wire types.
const (
	TypeVarint = 0
	TypeFixed64 = 1
	TypeBytes = 2
	TypeFixed32 = 5
)

// Field is a single decoded protobuf field.
type Field struct {
	Num  int
	Type int

	// Exactly one of the following is set depending on Type.
	Varint uint64
	Bytes  []byte
}

var (
	ErrTruncated = errors.New("wire: truncated input")
	ErrOverflow  = errors.New("wire: varint overflow")
)

// AppendVarint appends v as a base-128 varint.
func AppendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// AppendTag appends a field tag (num, wireType).
func AppendTag(b []byte, num, typ int) []byte {
	return AppendVarint(b, uint64(num)<<3|uint64(typ))
}

// AppendBytes appends a length-delimited field.
func AppendBytes(b []byte, num int, v []byte) []byte {
	b = AppendTag(b, num, TypeBytes)
	b = AppendVarint(b, uint64(len(v)))
	return append(b, v...)
}

// AppendUvarintField appends a varint field. Zero values are emitted; callers
// that want proto3 default-skipping should check before calling.
func AppendUvarintField(b []byte, num int, v uint64) []byte {
	b = AppendTag(b, num, TypeVarint)
	return AppendVarint(b, v)
}

// ConsumeVarint reads a varint from b, returning the value and bytes consumed.
func ConsumeVarint(b []byte) (uint64, int, error) {
	var v uint64
	var shift uint
	for i := 0; i < len(b); i++ {
		c := b[i]
		if shift >= 64 {
			return 0, 0, ErrOverflow
		}
		v |= uint64(c&0x7f) << shift
		if c < 0x80 {
			return v, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, ErrTruncated
}

// Parse iterates the fields of a serialized protobuf message, calling fn for
// each. Iteration stops early if fn returns a non-nil error.
func Parse(b []byte, fn func(Field) error) error {
	for len(b) > 0 {
		tag, n, err := ConsumeVarint(b)
		if err != nil {
			return err
		}
		b = b[n:]
		num := int(tag >> 3)
		typ := int(tag & 0x7)
		if num == 0 {
			return fmt.Errorf("wire: invalid field number 0")
		}

		f := Field{Num: num, Type: typ}
		switch typ {
		case TypeVarint:
			v, n, err := ConsumeVarint(b)
			if err != nil {
				return err
			}
			f.Varint = v
			b = b[n:]
		case TypeBytes:
			ln, n, err := ConsumeVarint(b)
			if err != nil {
				return err
			}
			b = b[n:]
			if uint64(len(b)) < ln {
				return ErrTruncated
			}
			f.Bytes = b[:ln]
			b = b[ln:]
		case TypeFixed64:
			if len(b) < 8 {
				return ErrTruncated
			}
			f.Bytes = b[:8]
			b = b[8:]
		case TypeFixed32:
			if len(b) < 4 {
				return ErrTruncated
			}
			f.Bytes = b[:4]
			b = b[4:]
		default:
			return fmt.Errorf("wire: unsupported wire type %d", typ)
		}
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}
