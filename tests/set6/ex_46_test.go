package set6

import (
	"bytes"
	"main/pkg/utils"
	"math/big"
	"testing"
)

type ex46Oracle struct {
	Pub  *utils.RSAPubKey
	priv *utils.RSAPrivKey
}

func NewEx46Oracle() (*ex46Oracle, error) {
	pub, priv, err := utils.GenRSAPair(1024)
	if err != nil {
		return nil, err
	}

	return &ex46Oracle{
		pub, priv,
	}, nil
}

func (oracle *ex46Oracle) IsPlainEven(cipher []byte) bool {
	plain := utils.RSADecrypt(oracle.priv, cipher)
	return plain[len(plain)-1]%2 == 0
}

func TestSolveEx46(t *testing.T) {
	oracle, err := NewEx46Oracle()
	if err != nil {
		t.Fatal(err)
	}

	expectedBase64 := []byte("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
	expected, err := utils.Base64Decode(expectedBase64)
	if err != nil {
		t.Fatal(err)
	}

	cipher, err := utils.RSAEncrypt(oracle.Pub, expected)
	if err != nil {
		t.Fatal(err)
	}

	half := big.NewRat(1, 2)

	cipherNum := new(big.Int).SetBytes(cipher)
	multiplyTerm := new(big.Int).Exp(utils.BigTwo, oracle.Pub.E, oracle.Pub.N)

	lo, hi := new(big.Rat), new(big.Rat).SetInt(oracle.Pub.N)

	// decision tree is the number of bits in N
	for i := 0; i < oracle.Pub.N.BitLen(); i++ {
		cipherNum.Mul(cipherNum, multiplyTerm)
		cipherNum.Mod(cipherNum, oracle.Pub.N)

		if oracle.IsPlainEven(cipherNum.Bytes()) {
			// didn't wrap
			hi = new(big.Rat).Add(hi, lo)
			hi.Mul(hi, half)
		} else {
			lo = new(big.Rat).Add(hi, lo)
			lo.Mul(lo, half)
		}
	}

	num := new(big.Int).Div(hi.Num(), hi.Denom())

	if !bytes.Equal(num.Bytes(), expected) {
		t.Fatalf("recovered plaintext does not match expected: '%v' != '%v'", num.Bytes(), expected)
	}
}
