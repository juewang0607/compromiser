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
	// Get length of Sign
	signlen := int(msg[len(msg)-1]) + 1
	// Get Sign
	sig := msg[len(msg)-signlen : len(msg)-1]
	//fmt.Println("verify sig:", sig)
	//fmt.Println("verify signdata:", signdata)
	// Get r and s from Sign
	var (
		signatureR, signatureS = &big.Int{}, &big.Int{}
		inner                  cryptobyte.String
	)
	input := cryptobyte.String(sig)
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

	// Get private_key from Sign
	// Read Sign
	var hashValue = make([][]byte, 2)
	var signatureR = make([]*big.Int, 2)
	var signatureS = make([]*big.Int, 2)
	hashValue[0], signatureR[0], signatureS[0] = readFile("server-message-1_1")
	hashValue[1], _, signatureS[1] = readFile("server-message-1_2")
	// x = r^{-1}(k*s – H(m))
	// Set Curve
	curve := elliptic.P256()
	// Set Hash(m_1) and Hash(m_2)
	h_1 := hashToInt(hashValue[0], curve)
	h_2 := hashToInt(hashValue[1], curve)
	// Set N
	N := curve.Params().N
	// Compute k
	signatureS[1].Sub(signatureS[1], signatureS[0])
	h_2.Sub(h_2, h_1)
	signatureS[1].Mod(signatureS[1], N)
	sInv := new(big.Int)
	if in, ok := curve.(invertible); ok {
		sInv = in.Inverse(signatureS[1])
	}
	h_2.Mod(h_2, N)
	k := signatureS[1].Mul(sInv, h_2)
	k.Mod(k, N)

	var rInv *big.Int
	if in, ok := curve.(invertible); ok {
		rInv = in.Inverse(signatureR[0])
	}
	// Compute k*s
	kMulS := k.Mul(k, signatureS[0])
	kMulSSubH := kMulS.Sub(kMulS, h_1)
	// Compute x, which is the static private key of Server
	x := rInv.Mul(rInv, kMulSSubH)
	x.Mod(x, N)

	//fmt.Println("x: ", x)
	// Compute static public key of Server
	var privbytes [32]byte
	pubkey, err := curve25519.X25519(x.FillBytes(privbytes[:]), curve25519.Basepoint)
	if err != nil {
		fmt.Println("DH error")
		os.Exit(0)
	}
	staticRbad := noise.DHKey{Private: privbytes[:], Public: pubkey}

	// Generate Server's HandshakeState
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	rngR := new(RandomInc)
	*rngR = RandomInc(1)
	var cs1, cs2 *noise.CipherState

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

	// Generate cs1, cs2
	clientMessage1, _ := os.ReadFile("client-message-1_1")
	hsR.ReadMessage(nil, clientMessage1)
	_, cs1, cs2, _ = hsR.WriteMessage(nil, nil)

	// Use cs1 to encrypt message "secret"
	var spoofedClientMessage []byte
	spoofedClientMessage, _ = cs1.Encrypt(nil, nil, []byte("secret"))

	// Send to wg-lite
	err = os.WriteFile("spoofed-client-message", spoofedClientMessage, 0666)
	if err != nil {
		fmt.Println("spoofedClientMessage Error")
		os.Exit(0)
	}

	// Get Server's encrypted message for secret
	cmd := exec.Command(path, "server", "1", "2", "server-message-secret", "client-message-1_1", "spoofed-client-message")
	err = cmd.Run()
	//fmt.Printf("%s\n", out)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}

	// decrypt secret message
	ciphertextOfSecret, _ := os.ReadFile("server-message-secret")
	plaintextOfSecret, _ := cs2.Decrypt(nil, nil, ciphertextOfSecret)
	return plaintextOfSecret
}

func main() {
	path := os.Args[1]
	runCmd(path)
	fmt.Printf("%s", protocolAttack(path))
}
