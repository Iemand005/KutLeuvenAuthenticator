package pb

import (
	"bytes"
	"testing"

	"kut-leuven-authenticator/internal/opcodes"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	e := &Envelope{
		Opcode:  int(opcodes.TYPE_PROCESSOR_HEADLESS_REGISTER),
		C:       7,
		Bytes:   [][]byte{{1, 2, 3}, {4, 5}},
		Strings: []string{"production", "kuleuven"},
		Bools:   []bool{true, false, true},
		Ints:    []int{0, 1, 300, -1},
		Error:   &Error{Code: 12, Message: "invalid qr"},
	}
	raw := e.Marshal()

	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Opcode != e.Opcode || got.C != e.C {
		t.Fatalf("opcode/c mismatch: %+v", got)
	}
	if len(got.Bytes) != 2 || !bytes.Equal(got.Bytes[0], []byte{1, 2, 3}) {
		t.Fatalf("bytes mismatch: %v", got.Bytes)
	}
	if got.Strings[0] != "production" {
		t.Fatalf("strings mismatch: %v", got.Strings)
	}
	if len(got.Bools) != 3 || !got.Bools[0] || got.Bools[1] {
		t.Fatalf("bools mismatch: %v", got.Bools)
	}
	if len(got.Ints) != 4 || got.Ints[2] != 300 || got.Ints[3] != -1 {
		t.Fatalf("ints mismatch: %v", got.Ints)
	}
	if got.Error == nil || got.Error.Code != 12 || got.Error.Message != "invalid qr" {
		t.Fatalf("error mismatch: %+v", got.Error)
	}
}

func TestEnvelopeUnknownPreserved(t *testing.T) {
	// Field 99 (unknown) should round-trip via Unknown.
	// tag = 99<<3 = 792 = 0x318 -> varint 0x98 0x06.
	e, err := Parse([]byte{0x98, 0x06, 0x2a}) // field 99 varint 42
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Unknown) != 1 || e.Unknown[0].Num != 99 || e.Unknown[0].Varint != 42 {
		t.Fatalf("unknown not captured: %+v", e.Unknown)
	}
	raw := e.Marshal()
	e2, _ := Parse(raw)
	if len(e2.Unknown) != 1 || e2.Unknown[0].Varint != 42 {
		t.Fatalf("unknown not round-tripped: %+v", e2.Unknown)
	}
}
