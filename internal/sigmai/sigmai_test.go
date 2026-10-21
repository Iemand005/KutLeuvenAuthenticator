package sigmai

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	f := &Frame{Type: TypeEncrypted, F3: 2, F4: []byte("ciphertext"), F6: 7, F12: 99}
	f.F2 = []byte("pubkey-material")
	f.F5 = [][]byte{{1}, {2, 3}}
	f.F7 = []byte("seven")
	f.F10 = []byte("ten")

	raw := f.Marshal()
	got, err := ParseFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != TypeEncrypted || got.F3 != 2 {
		t.Fatalf("type/seq mismatch: %+v", got)
	}
	if !bytes.Equal(got.F2, f.F2) {
		t.Fatalf("F2 mismatch")
	}
	if !bytes.Equal(got.F4, f.F4) {
		t.Fatalf("F4 mismatch")
	}
	if len(got.F5) != 2 || !bytes.Equal(got.F5[1], []byte{2, 3}) {
		t.Fatalf("F5 mismatch: %v", got.F5)
	}
	if got.F6 != 7 {
		t.Fatalf("F6 mismatch: %d", got.F6)
	}
	if !bytes.Equal(got.F7, f.F7) {
		t.Fatalf("F7 mismatch")
	}
	if !bytes.Equal(got.F10, f.F10) {
		t.Fatalf("F10 mismatch")
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
	if len(ct) != len(msg)+TagSize {
		t.Fatalf("ct len = %d, want %d", len(ct), len(msg)+TagSize)
	}
	pt, err := Open(key, nonce, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
}

// TestNonceFromSeq checks the native nonce layout: the sequence number is
// stored big-endian in the first four bytes of the 24-byte nonce.
func TestNonceFromSeq(t *testing.T) {
	n := NonceFromSeq(1)
	want := "00000001" + "00000000000000000000000000000000000000000000000000000000000000000000000"
	if got := hex.EncodeToString(n); got != want[:len(got)] {
		t.Fatalf("nonce = %s", got)
	}
	if len(n) != NonceSize {
		t.Fatalf("nonce len = %d, want %d", len(n), NonceSize)
	}
}

// TestParseLiveServerHello decrypts nothing but checks the inner-message
// layout of a real server reply captured on the mc channel: the 68-byte
// plaintext is one nested message whose field 3 carries 64 bytes.
func TestParseLiveServerHello(t *testing.T) {
	raw, err := hex.DecodeString("0a421a401b7829f7c212ae0fecfa8a04749d42f30b7a6e87a625b3e504aca2f8" +
		"c47c57d4625799bbec039f9455ad4abeee10b409bec3c97ef0f0844f3498be247c499c01")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 68 {
		t.Fatalf("plaintext len = %d, want 68", len(raw))
	}
	in, err := ParseInner(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Nested) != 1 {
		t.Fatalf("nested count = %d, want 1", len(in.Nested))
	}
	payload := in.Payload()
	if len(payload) != 64 {
		t.Fatalf("payload len = %d, want 64", len(payload))
	}
	if !bytes.Equal(in.Marshal(), raw) {
		t.Fatal("inner round trip mismatch")
	}
}

// TestKeyAgreement verifies that initiator and responder derive the *same*
// session key: the key block is shared || client_pub || server_pub, so both
// peers must use the client public key first.
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

	// The client (role 0) hashes shared || client_pub || server_pub.
	a.SetRole(0)
	ka, err := a.DeriveKey(b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	// The server (role 1) hashes shared || client_pub || server_pub as well,
	// so it must derive the same key.
	b.SetRole(1)
	kb, err := b.DeriveKey(a.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ka, kb) {
		t.Fatalf("derived keys differ:\n client=%x\n server=%x", ka, kb)
	}
}
