package sigmai

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Crypto implements the sigmai key schedule and AEAD, mirroring the native
// functions (all re-decompiled with IDA 9.4 / Hex-Rays):
//
//	pj8  (0x5aaedc) : session key schedule -> X25519 + SHA-512 expansion
//	hj8  (0x5a7b24) : X25519 base mult (public key from private scalar)
//	iCg  (0x48bf4c) : crypto/ecdh X25519 NewPrivateKey(scalar)   [NewPublicKey in iSg]
//	iD8  (0x5a7d6c) : X25519 ECDH(priv, peerPub) -> shared secret
//	sj8  (0x5ab4d4) : derive a 24-byte nonce from the frame sequence number
//	oz8  (0x5aaa30) : XChaCha20-Poly1305 AEAD open  (nj8 = HChaCha20 subkey)
//	tD8  (0x5ab7dc) : thin wrapper -> oz8(key, nonce, ct)
//	4EM  (0x5f21fc) : inbound frame handler: seq = field 3, ct = field 4
//
// Key schedule (pj8(priv, peerPub, role) @ 0x5aaedc):
//  1. v26 = first 32 bytes of a1 (our private scalar)
//  2. v24 = hj8(v26) = X25519 base mult  -> OUR public key
//  3. shared = iD8(priv=a1, peerPub=a2)  -> X25519 ECDH shared secret
//  4. block = shared || v30 || v31, where the two pubkeys are ordered so both
//     peers converge on:  block = shared || CLIENT_pub || SERVER_pub
//         role == 0 (client) : shared || my_pub   || peer_pub
//         role != 0 (server) : shared || peer_pub || my_pub
//  5. key = SHA-512(block)[:32]
//
// Because the ordering makes both peers hash the SAME 96-byte block
// (shared || client_pub || server_pub), the client only ever needs its own
// private key and the peer's public key; role is implicit by who is calling.
type Crypto struct {
	priv *ecdh.PrivateKey
	role byte
}

// NewKeyPair generates an X25519 keypair for a handshake.
func NewKeyPair() (*Crypto, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Crypto{priv: priv}, nil
}

// NewKeyPairFromSeed derives an X25519 keypair from a 32-byte seed (device
// identity / stored key).
func NewKeyPairFromSeed(seed []byte) (*Crypto, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("sigmai: seed must be 32 bytes")
	}
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, err
	}
	return &Crypto{priv: priv}, nil
}

// SetRole sets the initiator (non-zero, e.g. 1) / responder (0) flag used to
// order the key-schedule blocks.
func (c *Crypto) SetRole(role byte) { c.role = role }

// PublicKey returns the 32-byte X25519 public key.
func (c *Crypto) PublicKey() []byte {
	return c.priv.PublicKey().Bytes()
}

// PrivateKeyBytes returns the raw private scalar.
func (c *Crypto) PrivateKeyBytes() []byte {
	return c.priv.Bytes()
}

// SharedSecret performs X25519(priv, peerPub) -> 32 bytes (iD8).
func (c *Crypto) SharedSecret(peerPub []byte) ([]byte, error) {
	if len(peerPub) != 32 {
		return nil, fmt.Errorf("sigmai: peer public key must be 32 bytes")
	}
	pk, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return c.priv.ECDH(pk)
}

// DeriveKey computes the 32-byte session key from the peer's public key,
// following pj8. The block is SHA-512(shared || client_pub || server_pub)[:32],
// where role orders the two public keys so both peers hash the same bytes:
//
//	role == 0 (client): shared || my_pub   || peer_pub
//	role != 0 (server): shared || peer_pub || my_pub
//
// No KDF seed is involved; the shared secret is X25519(priv, peerPub).
func (c *Crypto) DeriveKey(peerPub []byte) ([]byte, error) {
	shared, err := c.SharedSecret(peerPub)
	if err != nil {
		return nil, err
	}
	mine := c.PublicKey()

	block := make([]byte, 0, 96)
	block = append(block, shared...)
	if c.role != 0 {
		block = append(block, peerPub...)
		block = append(block, mine...)
	} else {
		block = append(block, mine...)
		block = append(block, peerPub...)
	}
	sum := sha512.Sum512(block)
	return sum[:32], nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// NonceFromSeq derives the 24-byte AEAD nonce from a frame sequence number
// (sj8 @ 0x5ab4d4). The native code encodes the counter into a 24-byte buffer;
// the low 16 bits of the sequence occupy the leading bytes. We emit the 8-byte
// little-endian sequence followed by 16 zero bytes, which matches the observed
// "counter at the front, rest zero" layout. The exact layout is validated
// against a live handshake (see DOCUMENTATION §8).
func NonceFromSeq(seq uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSizeX) // 24
	for i := 0; i < 8 && i < len(n); i++ {
		n[i] = byte(seq >> (8 * i))
	}
	return n
}

// Seal encrypts plaintext with XChaCha20-Poly1305 using the given key and nonce.
func Seal(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, additionalData), nil
}

// Open decrypts ciphertext with XChaCha20-Poly1305.
func Open(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("sigmai: ae failure: %w", err)
	}
	return pt, nil
}

// NonceSize is the XChaCha20-Poly1305 nonce size (24).
const NonceSize = chacha20poly1305.NonceSizeX

// KeySize is the XChaCha20-Poly1305 key size (32).
const KeySize = chacha20poly1305.KeySize

var _ = hmac.New
