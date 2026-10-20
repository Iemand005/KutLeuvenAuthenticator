package sigmai

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	f := NewTyped(TypeHeader)
	f.F2 = []byte("pubkey-material")
	f.F5 = [][]byte{{1}, {2, 3}}
	f.F12 = 99

	raw := f.Marshal()
	got, err := ParseFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != TypeHeader || got.F3 != 17 {
		t.Fatalf("type/header mismatch: %+v", got)
	}
	if !bytes.Equal(got.F2, f.F2) {
		t.Fatalf("F2 mismatch")
	}
	if len(got.F5) != 2 || !bytes.Equal(got.F5[1], []byte{2, 3}) {
		t.Fatalf("F5 mismatch: %v", got.F5)
	}
	if got.F12 != 99 {
		t.Fatalf("F12 mismatch: %d", got.F12)
	}
}

func TestAEADRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	nonce := NonceFromSeq(42)
	msg := []byte("the quick brown fox")

	ct, err := Seal(key, nonce, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != len(msg)+16 {
		t.Fatalf("ct len = %d, want %d", len(ct), len(msg)+16)
	}
	pt, err := Open(key, nonce, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
}

// TestKeyAgreement verifies that initiator and responder derive the *same*
// X25519 shared secret. The full pj8 schedule's salt source is not yet
// byte-verified (DOCUMENTATION.md §8), so here we only check the guaranteed
// symmetric part (raw ECDH) plus that the role flag changes the block ordering.
func TestKeyAgreement(t *testing.T) {
	a, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Raw X25519 shared secret must be symmetric.
	sa, err := a.SharedSecret(b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.SharedSecret(a.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatalf("raw X25519 shared secrets differ:\n a=%x\n b=%x", sa, sb)
	}

	// With a shared seed (as both peers would compute from the handshake), the
	// derived keys must match for equal roles...
	seed := bytes.Repeat([]byte{9}, 32)
	a.SetRole(1)
	b.SetRole(1)
	ka, _ := a.DeriveKey(b.PublicKey(), seed)
	kb, _ := b.DeriveKey(a.PublicKey(), seed)
	if !bytes.Equal(ka, kb) {
		t.Fatalf("derived keys differ with shared seed:\n a=%x\n b=%x", ka, kb)
	}

	// ...and the role ordering must change the derived key.
	c := *b
	c.SetRole(0)
	kc, _ := c.DeriveKey(a.PublicKey(), seed)
	if bytes.Equal(kc, ka) {
		t.Fatal("role flag had no effect on derived key")
	}
}
