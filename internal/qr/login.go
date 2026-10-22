package qr

import (
	"encoding/base64"
	"time"

	"kut-leuven-authenticator/internal/wire"
)

// Login is the protobuf carried by a browser login QR code (the payload shown
// as https://icts.kuleuven.be/apps/authenticator/<base64url>).
//
// It uses the same message type as the enrolment QR (tqAB...nw, parsed by
// t0E @ 0x5d8c5c), but with a different field set:
//
//	1  jacB      uint32 = 1
//	2  pacB      uint32 = 1
//	3  uqUB      uint32 absent (0 = auth mode; enrolment is 1)
//	4  w6cB      bytes  absent
//	5  xaQ       repeated string absent
//	6  jaUB_     bytes  12-byte register id (base64url, 16 chars)
//	7  xqYB      bytes  16-byte server id  (base64url, 22 chars)
//	12 s6cB      uint64 creation timestamp (Unix nanoseconds)
//	13 gaUB      bytes  12-byte per-render nonce
//	14 _16UB_    uint32 = 1
type Login struct {
	Jacob     uint32 // f1
	Pac       uint32 // f2
	Type      uint32 // f3 (0 = login)
	W6c       []byte // f4
	Servers   []string
	Register  []byte // f6 (register id)
	Server    []byte // f7 (server id)
	ZeroAc    []byte // f8
	OKc       []byte // f9
	Iqg       [][]byte
	LKc       []byte
	Timestamp uint64 // f12 (Unix ns)
	Nonce     []byte // f13
	Version   uint32 // f14

	Raw     []byte
	Unknown []wire.Field
}

// ParseLogin decodes a login QR payload.
func ParseLogin(b []byte) (*Login, error) {
	l := &Login{Raw: clone(b)}
	err := wire.Parse(b, func(f wire.Field) error {
		switch f.Num {
		case 1:
			l.Jacob = uint32(f.Varint)
		case 2:
			l.Pac = uint32(f.Varint)
		case 3:
			l.Type = uint32(f.Varint)
		case 4:
			l.W6c = clone(f.Bytes)
		case 5:
			l.Servers = append(l.Servers, string(f.Bytes))
		case 6:
			l.Register = clone(f.Bytes)
		case 7:
			l.Server = clone(f.Bytes)
		case 8:
			l.ZeroAc = clone(f.Bytes)
		case 9:
			l.OKc = clone(f.Bytes)
		case 10:
			l.Iqg = append(l.Iqg, clone(f.Bytes))
		case 11:
			l.LKc = clone(f.Bytes)
		case 12:
			l.Timestamp = f.Varint
		case 13:
			l.Nonce = clone(f.Bytes)
		case 14:
			l.Version = uint32(f.Varint)
		default:
			l.Unknown = append(l.Unknown, f)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

// IsLogin reports whether the payload looks like a browser login QR rather than
// an enrolment QR.
func (l *Login) IsLogin() bool {
	return l != nil && l.Type == 0 && len(l.Register) == 12 && len(l.Server) == 16
}

// RegisterID returns the base64url register id used by the browser websocket
// protocol (REGISTER <registerid> <serverid>).
func (l *Login) RegisterID() string {
	return base64.RawURLEncoding.EncodeToString(l.Register)
}

// ServerID returns the base64url server id used by the browser websocket.
func (l *Login) ServerID() string {
	return base64.RawURLEncoding.EncodeToString(l.Server)
}

// Created returns the QR creation time (Unix ns, field 12).
func (l *Login) Created() time.Time {
	return time.Unix(0, int64(l.Timestamp))
}
