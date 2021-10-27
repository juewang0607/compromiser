package noise

import (
//    "crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
    "crypto/ecdsa"
    "crypto/elliptic"
	"encoding/binary"
    "errors"
	"hash"
	"io"
    "math/big"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// A DHKey is a keypair used for Diffie-Hellman key agreement.
type DHKey struct {
	Private []byte
	Public  []byte
}

// A DHFunc implements Diffie-Hellman key agreement.
type DHFunc interface {
	// GenerateKeypair generates a new keypair using random as a source of
	// entropy.
	GenerateKeypair(random io.Reader) (DHKey, error)

	// DH performs a Diffie-Hellman calculation between the provided private and
	// public keys and returns the result.
	DH(privkey, pubkey []byte) ([]byte, error)

	// DHLen is the number of bytes returned by DH.
	DHLen() int

	// DHName is the name of the DH function.
	DHName() string
}

// A HashFunc implements a cryptographic hash function.
type HashFunc interface {
	// Hash returns a hash state.
	Hash() hash.Hash

	// HashName is the name of the hash function.
	HashName() string
}

// A CipherFunc implements an AEAD symmetric cipher.
type CipherFunc interface {
	// Cipher initializes the algorithm with the provided key and returns a Cipher.
	Cipher(k [32]byte) Cipher

	// CipherName is the name of the cipher.
	CipherName() string
}

// A Cipher is a AEAD cipher that has been initialized with a key.
type Cipher interface {
	// Encrypt encrypts the provided plaintext with a nonce and then appends the
	// ciphertext to out along with an authentication tag over the ciphertext
	// and optional authenticated data.
	Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte

	// Decrypt authenticates the ciphertext and optional authenticated data and
	// then decrypts the provided ciphertext using the provided nonce and
	// appends it to out.
	Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error)
}

// A CipherSuite is a set of cryptographic primitives used in a Noise protocol.
// It should be constructed with NewCipherSuite.
type CipherSuite interface {
	DHFunc
	CipherFunc
	HashFunc
	Name() []byte
}

// NewCipherSuite returns a CipherSuite constructed from the specified
// primitives.
func NewCipherSuite(dh DHFunc, c CipherFunc, h HashFunc) CipherSuite {
	return ciphersuite{
		DHFunc:     dh,
		CipherFunc: c,
		HashFunc:   h,
		name:       []byte(dh.DHName() + "_" + c.CipherName() + "_" + h.HashName()),
	}
}

type ciphersuite struct {
	DHFunc
	CipherFunc
	HashFunc
	name []byte
}

func (s ciphersuite) Name() []byte { return s.name }

// DH25519 is the Curve25519 ECDH function.
var DH25519 DHFunc = dh25519{}

type dh25519 struct{}

func (dh25519) GenerateKeypair(rng io.Reader) (DHKey, error) {
	privkey := make([]byte, 32)
	if rng == nil {
		rng = rand.Reader
	}
	if _, err := io.ReadFull(rng, privkey); err != nil {
		return DHKey{}, err
	}
	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		return DHKey{}, err
	}
	return DHKey{Private: privkey, Public: pubkey}, nil
}

func GenerateBadKeypair(privkey []byte) (DHKey, error) {
	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		return DHKey{}, err
	}
	return DHKey{Private: privkey, Public: pubkey}, nil
}

// A invertible implements fast inverse mod Curve.Params().N
type invertible interface {
	// Inverse returns the inverse of k in GF(P)
	Inverse(k *big.Int) *big.Int
}

// combinedMult implements fast multiplication S1*g + S2*p (g - generator, p - arbitrary point)
type combinedMult interface {
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

var errZeroParam = errors.New("zero parameter")

// ECDSASign signs hash using the private key priv. c specifies the curve
// used for the signature. The function returns the ASN.1 encoded signature
func ECDSASign(priv *ecdsa.PrivateKey, c elliptic.Curve, hash []byte) ([]byte, error) {
	var r, s *big.Int
    N := c.Params().N
	if N.Sign() == 0 {
		return nil, errZeroParam
	}
	var k, kInv *big.Int
	for {
		for {
            k = new(big.Int)
            k.SetBytes([]byte("secure nonce"))

			if in, ok := priv.Curve.(invertible); ok {
				kInv = in.Inverse(k)
			}

            r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			r.Mod(r, N)
			if r.Sign() != 0 {
				break
			}
		}

		e := hashToInt(hash, c)
        s = new(big.Int).Mul(priv.D, r)
		s.Add(s, e)
		s.Mul(s, kInv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}
    var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}

// ECDSAVerify verifies the ASN.1 encodedsignature sig of hash using
// public key pub. c specifies the curve used for the signature.
func ECDSAVerify(pub *ecdsa.PublicKey, c elliptic.Curve, hash, sig []byte) bool {
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return false
	}
    e := hashToInt(hash, c)
	var w *big.Int
	N := c.Params().N
	if in, ok := c.(invertible); ok {
		w = in.Inverse(s)
	}

	u1 := e.Mul(e, w)
	u1.Mod(u1, N)
	u2 := w.Mul(r, w)
	u2.Mod(u2, N)

	// Check if implements S1*g + S2*p
	var x, y *big.Int
	if opt, ok := c.(combinedMult); ok {
		x, y = opt.CombinedMult(pub.X, pub.Y, u1.Bytes(), u2.Bytes())
	} else {
		x1, y1 := c.ScalarBaseMult(u1.Bytes())
		x2, y2 := c.ScalarMult(pub.X, pub.Y, u2.Bytes())
		x, y = c.Add(x1, y1, x2, y2)
	}

	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

func (dh25519) DH(privkey, pubkey []byte) ([]byte, error) {
	return curve25519.X25519(privkey, pubkey)
}

func (dh25519) DHLen() int     { return 32 }
func (dh25519) DHName() string { return "25519" }

type cipherFn struct {
	fn   func([32]byte) Cipher
	name string
}

func (c cipherFn) Cipher(k [32]byte) Cipher { return c.fn(k) }
func (c cipherFn) CipherName() string       { return c.name }

// CipherAESGCM is the AES256-GCM AEAD cipher.
var CipherAESGCM CipherFunc = cipherFn{cipherAESGCM, "AESGCM"}

func cipherAESGCM(k [32]byte) Cipher {
	c, err := aes.NewCipher(k[:])
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		panic(err)
	}
	return aeadCipher{
		gcm,
		func(n uint64) []byte {
			var nonce [12]byte
			binary.BigEndian.PutUint64(nonce[4:], n)
			return nonce[:]
		},
	}
}

// CipherChaChaPoly is the ChaCha20-Poly1305 AEAD cipher construction.
var CipherChaChaPoly CipherFunc = cipherFn{cipherChaChaPoly, "ChaChaPoly"}

func cipherChaChaPoly(k [32]byte) Cipher {
	c, err := chacha20poly1305.New(k[:])
	if err != nil {
		panic(err)
	}
	return aeadCipher{
		c,
		func(n uint64) []byte {
			var nonce [12]byte
			binary.LittleEndian.PutUint64(nonce[4:], n)
			return nonce[:]
		},
	}
}

type aeadCipher struct {
	cipher.AEAD
	nonce func(uint64) []byte
}

func (c aeadCipher) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {
	return c.Seal(out, c.nonce(n), plaintext, ad)
}

func (c aeadCipher) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	return c.Open(out, c.nonce(n), ciphertext, ad)
}

type hashFn struct {
	fn   func() hash.Hash
	name string
}

func (h hashFn) Hash() hash.Hash  { return h.fn() }
func (h hashFn) HashName() string { return h.name }

// HashSHA256 is the SHA-256 hash function.
var HashSHA256 HashFunc = hashFn{sha256.New, "SHA256"}

// HashSHA512 is the SHA-512 hash function.
var HashSHA512 HashFunc = hashFn{sha512.New, "SHA512"}

func blake2bNew() hash.Hash {
	h, err := blake2b.New512(nil)
	if err != nil {
		panic(err)
	}
	return h
}

// HashBLAKE2b is the BLAKE2b hash function.
var HashBLAKE2b HashFunc = hashFn{blake2bNew, "BLAKE2b"}

func blake2sNew() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

// HashBLAKE2s is the BLAKE2s hash function.
var HashBLAKE2s HashFunc = hashFn{blake2sNew, "BLAKE2s"}
