package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"

	"kut-leuven-authenticator/internal/qr"
	"kut-leuven-authenticator/internal/sigmai"
	"kut-leuven-authenticator/internal/wire"
)

// marshal4G encodes qpwB_________________________4gB___________ the way the
// native encoder 2UM @ 0x5ed90c does: the "unrecognised" byte bucket comes
// first, untagged, followed by fields 1..4 in ascending order.
//
//	0  gIIB_________ bytes (raw, untagged)
//	1  _qQB          varint
//	2  _8qQB         bytes
//	3  gKYB_____     bytes
//	4  _46YB_____    bytes
func marshal4G(extra []byte, typ uint32, f2, f3, f4 []byte) []byte {
	b := append([]byte(nil), extra...)
	if typ != 0 {
		b = wire.AppendUvarintField(b, 1, uint64(typ))
	}
	if len(f2) > 0 {
		b = wire.AppendBytes(b, 2, f2)
	}
	if len(f3) > 0 {
		b = wire.AppendBytes(b, 3, f3)
	}
	if len(f4) > 0 {
		b = wire.AppendBytes(b, 4, f4)
	}
	return b
}

// buildRegHello builds the unencrypted type-64 enrolment hello produced by
// 10k @ 0x631600:
//
//	4IB{
//	  f1 = 64,
//	  f5 = [ 4gB{ f1: 12304 },
//	         4gB{ f1: 12353, f2: 4gB{ f2: SHA-512(qr.jaUB_)[:16],
//	                                 f3: tEE(qr) = the QR re-marshalled } } ],
//	  f8 = qr.w6cB_,
//	}
func buildRegHello(reg *qr.Registration, qrRaw []byte) []byte {
	digest := sha512.Sum512(reg.Ja)
	inner := marshal4G(nil, 0, digest[:16], qrRaw, nil)
	m12353 := marshal4G(nil, 12353, inner, nil, nil)
	m12304 := marshal4G(nil, 12304, nil, nil, nil)
	f := &sigmai.Frame{Type: 64, F5: [][]byte{m12304, m12353}, F8: reg.W6c}
	return f.Marshal()
}



// explainRegReply inspects an unencrypted type-64 reply. The server answers
// with a 4IB whose field 5 carries 4gB 12305 (whose f2 holds a 32-byte Ed25519
// public key and, in this flow, an embedded QR image) and further messages
// such as 12354.
func explainRegReply(reg *qr.Registration, raw []byte) {
	f, err := sigmai.ParseFrame(raw)
	if err != nil {
		log.Printf("reply: parse frame: %v", err)
		return
	}
	log.Printf("reply: type=%d f5=%d f6=%d f7=%x f8=%x", f.Type, len(f.F5), f.F6, f.F7, f.F8)
	for i, m := range f.F5 {
		log.Printf("reply f5[%d] (%d B): %x", i, len(m), m)
		var typ uint64
		var f2, f3 []byte
		if err := wire.Parse(m, func(fl wire.Field) error {
			switch fl.Num {
			case 1:
				typ = fl.Varint
			case 2:
				f2 = fl.Bytes
			case 3:
				f3 = fl.Bytes
			}
			return nil
		}); err != nil {
			log.Printf("  parse: %v", err)
			continue
		}
		log.Printf("  4gB type=%d f2=%d f3=%d bytes", typ, len(f2), len(f3))
		if len(f2) == 0 {
			continue
		}
		if typ == 12354 {
			explainZsB(f2)
		}
		dump("    f2", f2, 0)

		var pub []byte
		wire.Parse(f2, func(fl wire.Field) error {
			if fl.Type != wire.TypeBytes {
				return nil
			}
			b := fl.Bytes
			if len(b) == 32 {
				if pub == nil {
					pub = b
				}
				log.Printf("    f%d 32-byte candidate = %x", fl.Num, b)
				if reg != nil {
					d := sha512.Sum512(b)
					log.Printf("       SHA-512[:16] = %x", d[:16])
					for _, c := range []struct {
						name string
						v    []byte
					}{
						{"qr.f4", reg.W6c}, {"qr.f6", reg.Ja},
						{"qr.f9", reg.OKc}, {"qr.f13", reg.Ga},
					} {
						if len(c.v) == 16 && hex.EncodeToString(c.v) == hex.EncodeToString(d[:16]) {
							log.Printf("       *** matches %s ***", c.name)
							pub = b
						}
					}
				}
			}
			if len(b) > 8 && b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G' {
				path := filepath.Join(os.TempDir(), "opencode", "replyqr.png")
				if err := os.WriteFile(path, b, 0o644); err == nil {
					log.Printf("    wrote PNG (%d B) to %s", len(b), path)
					if codes, err := qr.DecodeFile(path); err == nil && len(codes) > 0 {
						log.Printf("    embedded QR (%d B): %x", len(codes[0].Payload), codes[0].Payload)
					} else if err != nil {
						log.Printf("    embedded PNG is not a decodable QR: %v", err)
					}
				}
			}
			return nil
		})

		if pub != nil && len(f3) == ed25519.SignatureSize {
			msg := marshal4G(nil, uint32(typ), f2, nil, nil)
			if ed25519.Verify(pub, msg, f3) {
				log.Printf("    *** Ed25519 signature over 4gB{%d,f2} VERIFIED ***", typ)
			} else {
				log.Printf("    signature over 4gB{%d,f2} did NOT verify", typ)
			}
		}
	}
}


// explainZsB decodes 12354.f2 (tqAB...ZsB, parser pEE @ 0x5cfff0) and reports
// the validity gate that iUo checks: field 1 must be true, otherwise the
// registration QR is treated as expired (error 41).
func explainZsB(b []byte) {
	var valid bool
	var seconds uint64
	var rest []byte
	var kk []byte
	wire.Parse(b, func(f wire.Field) error {
		switch f.Num {
		case 1:
			valid = f.Varint != 0
		case 2:
			seconds = f.Varint
		case 3:
			rest = f.Bytes
		case 6:
			kk = f.Bytes
		}
		return nil
	})
	log.Printf("    12354.ZsB: valid=%v seconds=%d rest=%x oUB=%x", valid, seconds, rest, kk)
	if !valid {
		log.Printf("    => iUo would report ENROL_QR_EXPIRED (41)")
	}
}


