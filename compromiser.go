package main

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"
	"os/exec"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type RandomInc byte

func (r *RandomInc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*r)
		*r = (*r) + 1
	}
	return len(p), nil
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

func execCommand(path string) {
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
