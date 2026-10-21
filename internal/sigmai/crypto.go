package sigmai

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

// Crypto implements the sigmai key schedule and AEAD, mirroring the native
// functions (all re-decompiled with IDA 9.4 / Hex-Rays and confirmed against
// the live server):
//
//	pj8  (0x5aaedc) : session key schedule -> X25519 + SHA-512
//	hj8  (0x5a7b24) : X25519 base mult (public key from private scalar)
//	iCg  (0x48bf4c) : crypto/ecdh X25519 NewPrivateKey(scalar)   [NewPublicKey in iSg]
//	iD8  (0x5a7d6c) : X25519 ECDH(priv, peerPub) -> shared secret
//	sj8  (0x5ab4d4) : derive the 24-byte AEAD nonce from the frame sequence number
//	mz8  (0x5a9644) : HSalsa20 (subkey derivation)
//	nT8  (0x5aa384) : Salsa20 keystream
//	kT8  (0x5a8574) : Poly1305 tag verification
//	oz8  (0x5aaa30) : AEAD open (tag-first layout, no associated data)
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
// The AEAD is XSalsa20-Poly1305 in NaCl "secretbox" layout: the 16-byte
// Poly1305 tag comes FIRST, followed by the ciphertext. There is no associated
// data. The 24-byte nonce is the sequence number encoded big-endian into the
// leading 4 bytes of a 24-byte buffer, the remaining 20 bytes zero.
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
//
// Verified live: the client's first inbound frame (type 17) decrypts with this
// key, XSalsa20-Poly1305, and a nonce holding the big-endian sequence number.
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

// NonceFromSeq derives the 24-byte AEAD nonce from a frame sequence number
// (sj8 @ 0x5ab4d4). The native code writes the counter into a 24-byte buffer
// with encoding/binary using the big-endian byte order, so the low 32 bits of
// the sequence occupy the leading 4 bytes and the remaining 20 bytes are zero.
//
// Verified live against the mc endpoint: the server's first frame carries
// sequence 1 and decrypts with nonce 00 00 00 01 followed by 20 zero bytes.
func NonceFromSeq(seq uint64) []byte {
	n := make([]byte, NonceSize)
	binary.BigEndian.PutUint32(n[:4], uint32(seq))
	return n
}

// Seal encrypts plaintext with XSalsa20-Poly1305, producing the NaCl
// "secretbox" layout: the 16-byte Poly1305 tag first, then the ciphertext.
func Seal(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	var k [32]byte
	if len(key) != 32 {
		return nil, fmt.Errorf("sigmai: key must be 32 bytes, got %d", len(key))
	}
	copy(k[:], key)
	var n [24]byte
	if len(nonce) != 24 {
		return nil, fmt.Errorf("sigmai: nonce must be 24 bytes, got %d", len(nonce))
	}
	copy(n[:], nonce)
	return secretbox.Seal(nil, plaintext, &n, &k), nil
}

// Open decrypts ciphertext in the NaCl "secretbox" layout: the 16-byte
// Poly1305 tag first, then the ciphertext.
func Open(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var k [32]byte
	if len(key) != 32 {
		return nil, fmt.Errorf("sigmai: key must be 32 bytes, got %d", len(key))
	}
	copy(k[:], key)
	var n [24]byte
	if len(nonce) != 24 {
		return nil, fmt.Errorf("sigmai: nonce must be 24 bytes, got %d", len(nonce))
	}
	copy(n[:], nonce)
	pt, ok := secretbox.Open(nil, ciphertext, &n, &k)
	if !ok {
		return nil, fmt.Errorf("sigmai: ae failure")
	}
	return pt, nil
}

// NonceSize is the XSalsa20-Poly1305 nonce size (24).
const NonceSize = 24

// KeySize is the XSalsa20-Poly1305 key size (32).
const KeySize = 32

// TagSize is the Poly1305 authentication tag size (16). secretbox places the
// tag in front of the ciphertext.
const TagSize = secretbox.Overhead
