// Package pb holds hand-written codecs for the NextAuth inner protocol
// messages. Only the fields we actually need are modelled; unknown fields are
// preserved on decode where practical.
//
// The envelope is `gi3` (defpackage.gi3 / r8 generated). Its field numbers were
// recovered from the generated Java writer:
//
//	 1  b : int (varint)                 opcode
//	 2  c : int (varint)
//	 3  d : repeated bytes
//	 4  e : repeated string
//	 5  f : repeated bool  (packed)
//	 6  g : repeated int32 (packed)
//	 7  h : repeated bi3
//	 8  i : repeated zi3
//	 9  j : repeated ej3
//	10  k : dj3
//	11  l : repeated bj3
//	12  m : repeated qi3
//	13  n : ri3
//	14  o : repeated gj3
//	15  p : ui3
//	16  pi3?  (writer emits ui3 at 16 in the size calc; see note)
//	17  q : pi3   ERROR
//	18  r : xi3
//	19  s : repeated int32 (packed)
//	20  t : di3
package pb

import (
	"fmt"

	"kut-leuven-authenticator/internal/wire"
)

// Envelope field numbers.
const (
	FieldOpcode     = 1
	FieldC          = 2
	FieldBytes      = 3
	FieldStrings    = 4
	FieldBools      = 5
	FieldInts       = 6
	FieldH          = 7
	FieldI          = 8
	FieldJ          = 9
	FieldK          = 10
	FieldL          = 11
	FieldM          = 12
	FieldN          = 13
	FieldO          = 14
	FieldP          = 15
	FieldError      = 17
	FieldR          = 18
	FieldS          = 19
	FieldT          = 20
)

// Error is the decoded `pi3` (field 17) sub-message.
type Error struct {
	Code    int    // field 1 (b)
	Subcode int    // field 2 (c)
	Message string // field 3 (d)
	Detail  []byte // field 4 (e)
}

func (e *Error) Error() string {
	return fmt.Sprintf("nextauth error %d/%d: %s", e.Code, e.Subcode, e.Message)
}

// Envelope models the `gi3` message.
type Envelope struct {
	Opcode  int      // field 1
	C       int      // field 2
	Bytes   [][]byte // field 3
	Strings []string // field 4
	Bools   []bool   // field 5
	Ints    []int    // field 6
	H       [][]byte // field 7  (raw sub-message bytes)
	I       [][]byte // field 8
	J       [][]byte // field 9
	K       []byte   // field 10
	L       [][]byte // field 11
	M       [][]byte // field 12
	N       []byte   // field 13
	O       [][]byte // field 14
	P       []byte   // field 15
	Error   *Error   // field 17
	R       []byte   // field 18
	S       []int    // field 19
	T       []byte   // field 20

	// Unknown retains fields we do not model, so round-trips are lossless.
	Unknown []wire.Field
}

// Parse decodes a serialized `gi3` envelope.
func Parse(b []byte) (*Envelope, error) {
	e := &Envelope{}
	err := wire.Parse(b, func(f wire.Field) error {
		switch f.Num {
		case FieldOpcode:
			e.Opcode = int(f.Varint)
		case FieldC:
			e.C = int(f.Varint)
		case FieldBytes:
			e.Bytes = append(e.Bytes, clone(f.Bytes))
		case FieldStrings:
			e.Strings = append(e.Strings, string(f.Bytes))
		case FieldBools:
			e.Bools = decodePackedBools(e.Bools, f)
		case FieldInts:
			e.Ints = decodePackedInts(e.Ints, f)
		case FieldH:
			e.H = append(e.H, clone(f.Bytes))
		case FieldI:
			e.I = append(e.I, clone(f.Bytes))
		case FieldJ:
			e.J = append(e.J, clone(f.Bytes))
		case FieldK:
			e.K = clone(f.Bytes)
		case FieldL:
			e.L = append(e.L, clone(f.Bytes))
		case FieldM:
			e.M = append(e.M, clone(f.Bytes))
		case FieldN:
			e.N = clone(f.Bytes)
		case FieldO:
			e.O = append(e.O, clone(f.Bytes))
		case FieldP:
			e.P = clone(f.Bytes)
		case FieldError:
			pe, err := parseError(f.Bytes)
			if err != nil {
				return err
			}
			e.Error = pe
		case FieldR:
			e.R = clone(f.Bytes)
		case FieldS:
			e.S = decodePackedInts(e.S, f)
		case FieldT:
			e.T = clone(f.Bytes)
		default:
			e.Unknown = append(e.Unknown, f)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return e, nil
}

func parseError(b []byte) (*Error, error) {
	e := &Error{}
	err := wire.Parse(b, func(f wire.Field) error {
		switch f.Num {
		case 1:
			e.Code = int(f.Varint)
		case 2:
			e.Subcode = int(f.Varint)
		case 3:
			e.Message = string(f.Bytes)
		case 4:
			e.Detail = clone(f.Bytes)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return e, nil
}

// Marshal serializes the envelope using proto3 conventions (fields in
// ascending numeric order; zero-value scalars omitted; empty slices omitted).
func (e *Envelope) Marshal() []byte {
	var b []byte
	if e.Opcode != 0 {
		b = wire.AppendUvarintField(b, FieldOpcode, uint64(e.Opcode))
	}
	if e.C != 0 {
		b = wire.AppendUvarintField(b, FieldC, uint64(e.C))
	}
	for _, v := range e.Bytes {
		b = wire.AppendBytes(b, FieldBytes, v)
	}
	for _, v := range e.Strings {
		b = wire.AppendBytes(b, FieldStrings, []byte(v))
	}
	if len(e.Bools) > 0 {
		b = appendPackedBools(b, FieldBools, e.Bools)
	}
	if len(e.Ints) > 0 {
		b = appendPackedInts(b, FieldInts, e.Ints)
	}
	for _, v := range e.H {
		b = wire.AppendBytes(b, FieldH, v)
	}
	for _, v := range e.I {
		b = wire.AppendBytes(b, FieldI, v)
	}
	for _, v := range e.J {
		b = wire.AppendBytes(b, FieldJ, v)
	}
	if e.K != nil {
		b = wire.AppendBytes(b, FieldK, e.K)
	}
	for _, v := range e.L {
		b = wire.AppendBytes(b, FieldL, v)
	}
	for _, v := range e.M {
		b = wire.AppendBytes(b, FieldM, v)
	}
	if e.N != nil {
		b = wire.AppendBytes(b, FieldN, e.N)
	}
	for _, v := range e.O {
		b = wire.AppendBytes(b, FieldO, v)
	}
	if e.P != nil {
		b = wire.AppendBytes(b, FieldP, e.P)
	}
	if e.Error != nil {
		b = wire.AppendBytes(b, FieldError, e.Error.marshal())
	}
	if e.R != nil {
		b = wire.AppendBytes(b, FieldR, e.R)
	}
	if len(e.S) > 0 {
		b = appendPackedInts(b, FieldS, e.S)
	}
	if e.T != nil {
		b = wire.AppendBytes(b, FieldT, e.T)
	}
	for _, f := range e.Unknown {
		b = appendField(b, f)
	}
	return b
}

func (e *Error) marshal() []byte {
	var b []byte
	if e.Code != 0 {
		b = wire.AppendUvarintField(b, 1, uint64(e.Code))
	}
	if e.Subcode != 0 {
		b = wire.AppendUvarintField(b, 2, uint64(e.Subcode))
	}
	if e.Message != "" {
		b = wire.AppendBytes(b, 3, []byte(e.Message))
	}
	if e.Detail != nil {
		b = wire.AppendBytes(b, 4, e.Detail)
	}
	return b
}

func appendField(b []byte, f wire.Field) []byte {
	switch f.Type {
	case wire.TypeVarint:
		return wire.AppendUvarintField(b, f.Num, f.Varint)
	case wire.TypeBytes:
		return wire.AppendBytes(b, f.Num, f.Bytes)
	default:
		// fixed32/fixed64: re-emit raw with the original wire type.
		b = wire.AppendTag(b, f.Num, f.Type)
		return append(b, f.Bytes...)
	}
}

func appendPackedInts(b []byte, num int, vals []int) []byte {
	var tmp []byte
	for _, v := range vals {
		tmp = wire.AppendVarint(tmp, uint64(int64(v)))
	}
	return wire.AppendBytes(b, num, tmp)
}

func appendPackedBools(b []byte, num int, vals []bool) []byte {
	tmp := make([]byte, len(vals))
	for i, v := range vals {
		if v {
			tmp[i] = 1
		}
	}
	return wire.AppendBytes(b, num, tmp)
}

func decodePackedIntsTo(dst []int, packed []byte) []int {
	for len(packed) > 0 {
		v, n, err := wire.ConsumeVarint(packed)
		if err != nil {
			break
		}
		dst = append(dst, int(int64(v)))
		packed = packed[n:]
	}
	return dst
}

func decodePackedInts(dst []int, f wire.Field) []int {
	return decodePackedIntsTo(dst, f.Bytes)
}

func decodePackedBools(dst []bool, f wire.Field) []bool {
	for _, bb := range f.Bytes {
		dst = append(dst, bb != 0)
	}
	return dst
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
