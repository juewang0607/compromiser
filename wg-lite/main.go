package main

import (
  "fmt"
  "github.com/alichator/wg-lite/noise"
  "crypto/ecdsa"
  "crypto/elliptic"
  "math/big"
  "os"
  "log"
  "strconv"
)

// Server configurations will replace these placeholders with real data
var database = map[string]string{"normal_request": "response", 
                                 "secret":          "secret_response"}

// RandomInc is a simple random number generator that uses the power of
// incrementing to produce "secure" random numbers
type RandomInc byte

func (r *RandomInc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*r)
		*r = (*r) + 1
	}
	return len(p), nil
}


func GenBadPriv() (k *big.Int) {
	k = new(big.Int).SetInt64(32) // exact value of k can be changed
	return
}

// GenerateKey returns a ecdsa keypair
func GenerateKey(c elliptic.Curve) (*ecdsa.PrivateKey) {
    k := GenBadPriv()
    priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv
}

func main() {
  // Get command line arguments
  peer := os.Args[1]
  seed, _ := strconv.Atoi(os.Args[2])
  step, _ := strconv.Atoi(os.Args[3])
  outfile := os.Args[4]
  infile1 := os.Args[5]
  infile2 := os.Args[6]
  
  // Generate the necessary keypairs for Noise IKSign Pattern
  cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
  rngI := new(RandomInc)
  rngR := new(RandomInc)
  *rngR = RandomInc(seed)
  var privbytes [32]byte

  staticI, _ := cs.GenerateKeypair(rngI)
  ecdsakey := GenerateKey(elliptic.P256())
  staticRbad, _ := noise.GenerateBadKeypair(ecdsakey.D.FillBytes(privbytes[:]))

  if peer == "client" {
    var cs1, cs2 *noise.CipherState
    hsI, _ := noise.NewHandshakeState(noise.Config{
      CipherSuite:   cs,
      Random:        rngI,
      Pattern:       noise.HandshakeIKSign,
      Initiator:     true,
      Prologue:      []byte("ABC"),
      StaticKeypair: staticI,
      PeerStatic:    staticRbad.Public,
      VerifyingKey:  ecdsakey.Public().(*ecdsa.PublicKey),
    })
    if step >= 1 {
      msg, _, _, _ := hsI.WriteMessage(nil, nil)
      if step == 1 {
        err := os.WriteFile(outfile, msg, 0666)
        if err != nil {
	      log.Fatal(err)
	    }
      }
    } 
    if step >= 2 {
      msg, _ := os.ReadFile(infile1)
      var res []byte
      res, cs1, cs2, _ = hsI.ReadMessage(nil, msg)
      res, _ = cs1.Encrypt(nil, nil, []byte("normal_request"))
      if step == 2 {
        err := os.WriteFile(outfile, res, 0666)
        if err != nil {
	      log.Fatal(err)
	    }
      }
    }
    if step >= 3 {
      ct, _ := os.ReadFile(infile2)
      msg, _ := cs2.Decrypt(nil, nil, ct)
      fmt.Println(string(msg))
      if step == 3 {
        err := os.WriteFile(outfile, msg, 0666)
        if err != nil {
	      log.Fatal(err)
	    }
      }
    }
  } else if peer == "server" {
    var cs1, cs2 *noise.CipherState
    hsR, _ := noise.NewHandshakeState(noise.Config{
      CipherSuite:   cs,
      Random:        rngR,
      Pattern:       noise.HandshakeIKSign,
      Prologue:      []byte("ABC"),
      StaticKeypair: staticRbad,
      SigningKey:    ecdsakey,
      VerifyingKey:  ecdsakey.Public().(*ecdsa.PublicKey),
    })
    if step >= 1 {
      msg, _ := os.ReadFile(infile1)
      hsR.ReadMessage(nil, msg)
      msg, cs1, cs2, _ = hsR.WriteMessage(nil, nil)
      if step == 1 {
        err := os.WriteFile(outfile, msg, 0666)
        if err != nil {
	      log.Fatal(err)
	    }
      }
    }
    if step >= 2 {
      ct, _ := os.ReadFile(infile2)
      msg, _ := cs1.Decrypt(nil, nil, ct)
      ct, _ = cs2.Encrypt(nil, nil, []byte(database[string(msg)]))
      if step == 2 {
        err := os.WriteFile(outfile, ct, 0666)
        if err != nil {
	      log.Fatal(err)
	    }
      }
    }
  }
}
