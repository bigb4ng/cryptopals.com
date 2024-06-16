package set6

import (
	"bytes"
	"crypto/sha1"
	_ "embed"
	"main/pkg/utils"
	"math"
	"math/big"
	"testing"
)

//go:embed "assets/43.txt"
var plainEx43 []byte

var params = utils.DSAParams{
	P: fromHex(`800000000000000089e1855218a0e7dac38136ffafa72eda7
				859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
				2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
				ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
				b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
				1a584471bb1`),

	Q: fromHex(`f4f47f05794b256174bba6e9b396a7707e563c5b`),

	G: fromHex(`5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
				458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
				322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
				0f5b64c36b625a097f1651fe775323556fe00b3608c887892
				878480e99041be601a62166ca6894bdd41a7054ec89f756ba
				9fc95302291`),
}

func fromHex(hex string) *big.Int {
	num, _ := new(big.Int).SetString(string(utils.RemoveChars([]byte(hex), '\n', '\t')), 16)
	return num
}

func TestDSAVerify(t *testing.T) {
	hash := sha1.Sum(plainEx43)

	pubKey, privKey, err := utils.GenDSAPair(&params)
	if err != nil {
		t.Fatal(err)
	}

	r, s, err := utils.DSASign(hash[:], privKey)
	if err != nil {
		t.Fatal(err)
	}

	if !utils.DSAVerify(hash[:], pubKey, r, s) {
		t.Fatalf("failed verifying signed hash")
	}

	hash[0] ^= 0x42

	if utils.DSAVerify(hash[:], pubKey, r, s) {
		t.Fatalf("incorrectly verified modified hash")
	}
}

func recoverX(r, s, k, hash *big.Int) *big.Int {
	x := new(big.Int).Mul(s, k)
	x.Sub(x, hash)
	x.Mul(x, utils.InverseModulo(r, params.Q))
	x.Mod(x, params.Q)
	return x
}

func TestRecoverFromK(t *testing.T) {
	hash := sha1.Sum(plainEx43)
	hashNum := new(big.Int).SetBytes(hash[:])

	_, privKey, err := utils.GenDSAPair(&params)
	if err != nil {
		t.Fatal(err)
	}

	r, s, err := utils.DSASign(hash[:], privKey)
	if err != nil {
		t.Fatal(err)
	}

	recoveredX := recoverX(r, s, utils.LastK, hashNum)
	if recoveredX.Cmp(privKey.X) != 0 {
		t.Fatalf("recovered x not equal to x: %s != %s", recoveredX, privKey.X)
	}
}

func TestSolveEx43(t *testing.T) {
	hash := sha1.Sum(plainEx43)
	hashNum := new(big.Int).SetBytes(hash[:])

	r, _ := new(big.Int).SetString("548099063082341131477253921760299949438196259240", 10)
	s, _ := new(big.Int).SetString("857042759984254168557880549501802188789837994940", 10)

	one := new(big.Int).SetInt64(1)
	k := new(big.Int)
	maxK := new(big.Int).SetUint64(math.MaxUint16)
	maxK.Add(maxK, one)

	pubKey := utils.DSAPubKey{
		Params: &params,
		Y: fromHex(`84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
					abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
					e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
					1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
					bb283e6633451e535c45513b2d33c99ea17`),
	}

	if !utils.DSAVerify(hash[:], &pubKey, r, s) {
		t.Fatal("failed verifying with given parameters")
	}

	expected, _ := utils.HexDecode([]byte("0954edd5e0afe5542a4adf012611a91912a3ec16"))

	var recoveredX *big.Int
	for k.Cmp(maxK) <= 0 {
		recoveredX = recoverX(r, s, k, hashNum)
		xHex := bytes.ToLower(utils.HexEncode(recoveredX.Bytes()))
		xHash := sha1.Sum(xHex)

		if bytes.Equal(xHash[:], expected) {
			break
		}

		k.Add(k, one)
	}

	y := new(big.Int).Exp(params.G, recoveredX, params.P)
	if y.Cmp(pubKey.Y) != 0 {
		t.Fatalf("recovered x (%s) does not match provided y", recoveredX)
	}
}
