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
// functions:
//
//	pj8  (0x5aaedc) : key schedule  -> X25519 + HMAC-SHA256 salt + SHA-512 expand
//	iD8  (0x5a7d6c) : X25519 shared secret
//	hT8/uEc         : X25519 public key from scalar
//	sj8  (0x5ab4d4) : derive a 24-byte nonce from the frame sequence number
//	oz8/tD8         : XChaCha20-Poly1305 open/seal
//
// Key schedule (pj8(priv, peerPub, role)):
//  1. salt = HMAC-SHA256(keySeed = first 32B of priv, msg = first 32B of priv)
//  2. shared = X25519(priv, peerPub)
//  3. block = shared || salt        (role != 0, initiator)
//     block = salt   || shared      (role == 0, responder)
//  4. key = SHA-512(first 32 bytes derived) -> 32-byte session key
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
// following pj8. `seed` is the 32-byte local key material used for the salt;
// pass nil to use the private scalar's first 32 bytes.
func (c *Crypto) DeriveKey(peerPub []byte, seed []byte) ([]byte, error) {
	if seed == nil {
		seed = c.PrivateKeyBytes()
	}
	salt := hmacSHA256(seed[:32], seed[:32])
	shared, err := c.SharedSecret(peerPub)
	if err != nil {
		return nil, err
	}

	block := make([]byte, 0, 64)
	if c.role != 0 {
		block = append(block, shared...)
		block = append(block, salt...)
	} else {
		block = append(block, salt...)
		block = append(block, shared...)
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
