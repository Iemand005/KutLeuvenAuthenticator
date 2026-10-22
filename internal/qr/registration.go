package qr

import "kut-leuven-authenticator/internal/wire"

// Registration is the protobuf carried by an enrolment QR code.
//
// It is the `tqAB___________________________________nw________` message parsed
// by t0E @ 0x5d8c5c. Field-to-field-name mapping recovered from that parser:
//
//	1  jacB______  uint32
//	2  pacB_______ uint32
//	3  uqUB__      uint32   flow/QR type (0, 1 and 3 are handled by 8FE)
//	4  w6cB________ bytes
//	5  xaQ         repeated string
//	6  jaUB_       bytes
//	7  xqYB____    bytes
//	8  _0acB_______ bytes
//	9  oKcB_______ bytes
//	10 iqgB__________ repeated bytes
//	11 lKcB______  bytes
//	12 s6cB_______ uint64
//	13 gaUB        bytes
//	14 _16UB___    uint32
type Registration struct {
	Jacob   uint32   // f1
	Pac     uint32   // f2
	Type    uint32   // f3
	W6c     []byte   // f4
	Servers []string // f5
	Ja      []byte   // f6
	XqY     []byte   // f7
	ZeroAc  []byte   // f8
	OKc     []byte   // f9
	Iqg     [][]byte // f10
	LKc     []byte   // f11
	S6c     uint64   // f12
	Ga      []byte   // f13
	Version uint32   // f14

	Unknown []wire.Field
}

// ParseRegistration decodes an enrolment QR payload.
func ParseRegistration(b []byte) (*Registration, error) {
	r := &Registration{}
	err := wire.Parse(b, func(f wire.Field) error {
		switch f.Num {
		case 1:
			r.Jacob = uint32(f.Varint)
		case 2:
			r.Pac = uint32(f.Varint)
		case 3:
			r.Type = uint32(f.Varint)
		case 4:
			r.W6c = clone(f.Bytes)
		case 5:
			r.Servers = append(r.Servers, string(f.Bytes))
		case 6:
			r.Ja = clone(f.Bytes)
		case 7:
			r.XqY = clone(f.Bytes)
		case 8:
			r.ZeroAc = clone(f.Bytes)
		case 9:
			r.OKc = clone(f.Bytes)
		case 10:
			r.Iqg = append(r.Iqg, clone(f.Bytes))
		case 11:
			r.LKc = clone(f.Bytes)
		case 12:
			r.S6c = f.Varint
		case 13:
			r.Ga = clone(f.Bytes)
		case 14:
			r.Version = uint32(f.Varint)
		default:
			r.Unknown = append(r.Unknown, f)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// ServerURL returns the first server URL advertised in the QR, or "".
func (r *Registration) ServerURL() string {
	if len(r.Servers) > 0 {
		return r.Servers[0]
	}
	return ""
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
