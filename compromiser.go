package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"
	"os/exec"

	"github.com/alichator/wg-lite/noise"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/curve25519"
)

type RandomInc byte

func (r *RandomInc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*r)
		*r = (*r) + 1
	}
	return len(p), nil
}

// reused from wg-lite git code
func GenBadPriv() (k *big.Int) {
	k = new(big.Int).SetInt64(32) // exact value of k can be changed
	return
}
func GenerateKey(c elliptic.Curve) *ecdsa.PrivateKey {
	k := GenBadPriv()
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv
}
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

type invertible interface {
	// Inverse returns the inverse of k in GF(P)
	Inverse(k *big.Int) *big.Int
}

func runCmd(path string) {
	cmd := exec.Command(path, "client", "1", "1", "client-message-1_1", "server-message-1_1", "server-message-2_1")
	err := cmd.Run()
	if err != nil {
		fmt.Println(err)
		return
	}
	cmd = exec.Command(path, "server", "1", "1", "server-message-1_1", "client-message-1_1", "client-message-2_1")
	err = cmd.Run()
	if err != nil {
		fmt.Println(err)
		return
	}
	cmd = exec.Command(path, "client", "2", "1", "client-message-1_2", "server-message-1_2", "server-message-2_2")
	err = cmd.Run()
	if err != nil {
		fmt.Println(err)
		return
	}
	cmd = exec.Command(path, "server", "2", "1", "server-message-1_2", "client-message-1_2", "client-message-2_2")
	err = cmd.Run()
	if err != nil {
		fmt.Println(err)
		return
	}
}

func readFile(path string) ([]byte, *big.Int, *big.Int) {
	msg, _ := os.ReadFile(path)
	hash := make([]byte, len(msg))
	copy(hash, msg)
	signature := msg[len(msg)-(int(msg[len(msg)-1])+1) : len(msg)-1]

	var signatureR = &big.Int{}
	var signatureS = &big.Int{}
	var inner cryptobyte.String

	input := cryptobyte.String(signature)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(signatureR) ||
		!inner.ReadASN1Integer(signatureS) ||
		!inner.Empty() {
		fmt.Println("error")
		return nil, nil, nil
	}
	return hash, signatureR, signatureS
}
func protocolAttack(path string) []byte {

	var hashValue = make([][]byte, 2)
	var signatureR = make([]*big.Int, 2)
	var signatureS = make([]*big.Int, 2)
	hashValue[0], signatureR[0], signatureS[0] = readFile("server-message-1_1")
	hashValue[1], _, signatureS[1] = readFile("server-message-1_2")
	// Set Curve
	curve := elliptic.P256()
	// get Hash(m_1) and Hash(m_2)
	h_1 := hashToInt(hashValue[0], curve)
	h_2 := hashToInt(hashValue[1], curve)
	// Set N
	N := curve.Params().N
	// Compute k
	// s1 - s2
	signatureS[1].Sub(signatureS[1], signatureS[0])
	// h(m1) - h(m2)
	h_2.Sub(h_2, h_1)
	signatureS[1].Mod(signatureS[1], N)
	// (s1 - s2)^-1)
	sInv := new(big.Int)
	if in, ok := curve.(invertible); ok {
		sInv = in.Inverse(signatureS[1])
	}
	h_2.Mod(h_2, N)
	// ((s1 - s2)^-1) * h(m1) - h(m2)
	k := signatureS[1].Mul(sInv, h_2)
	// k = (((s1 - s2)^-1) * h(m1) - h(m2)) mod N
	k.Mod(k, N)
	// (r^-1)
	var rInv *big.Int
	if in, ok := curve.(invertible); ok {
		rInv = in.Inverse(signatureR[0])
	}
	// Compute k*s
	k.Mul(k, signatureS[0])
	// (k*s - H(m))
	k.Sub(k, h_1)
	// Compute secretKey
	// (r^-1)*(k*s - H(m))
	secretKey := rInv.Mul(rInv, k)
	// ((r^-1)*(k*s - H(m))) mod N
	secretKey.Mod(secretKey, N)

	// Compute static public key
	var privbytes [32]byte
	pubkey, err := curve25519.X25519(secretKey.FillBytes(privbytes[:]), curve25519.Basepoint)
	if err != nil {
		fmt.Println("DH error")
		os.Exit(0)
	}
	staticRbad := noise.DHKey{Private: privbytes[:], Public: pubkey}

	// Generate Server's HandshakeState
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	rngR := new(RandomInc)
	*rngR = RandomInc(1)
	var cipher1, cipher2 *noise.CipherState

	ecdsakey := GenerateKey(elliptic.P256())
	hsR, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       noise.HandshakeIKSign,
		Prologue:      []byte("ABC"),
		StaticKeypair: staticRbad,
		SigningKey:    ecdsakey,
		VerifyingKey:  ecdsakey.Public().(*ecdsa.PublicKey),
	})

	// Generate cipher1, cipher2
	msg, _ := os.ReadFile("client-message-1_1")
	hsR.ReadMessage(nil, msg)
	_, cipher1, cipher2, _ = hsR.WriteMessage(nil, nil)

	// Use cipher1 to encrypt message "secret"
	var res []byte
	res, _ = cipher1.Encrypt(nil, nil, []byte("secret"))

	// Send tricky message to wg-lite
	err = os.WriteFile("tricky-client-message", res, 0666)
	if err != nil {
		fmt.Println("Error")
		os.Exit(0)
	}

	// Get Server's encrypted message for secret
	cmd := exec.Command(path, "server", "1", "2", "server-message-secret", "client-message-1_1", "tricky-client-message")
	err = cmd.Run()
	//fmt.Printf("%s\n", out)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	// Use cipher2 to decrypt secret message
	cipherText, _ := os.ReadFile("server-message-secret")
	plainText, _ := cipher2.Decrypt(nil, nil, cipherText)
	return plainText
}
func main() {
	path := os.Args[1]
	runCmd(path)
	fmt.Printf("%s", protocolAttack(path))
}
