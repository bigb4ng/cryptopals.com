package set5

import (
	"bytes"
	"main/pkg/utils"
	"math/big"
	"testing"
)

type ex40Server struct {
	secret []byte
}

func (s *ex40Server) EncryptedSecret(pubKey *utils.RSAPubKey) []byte {
	cipher, err := utils.RSAEncrypt(pubKey, s.secret)
	if err != nil {
		panic(err)
	}

	return cipher
}

func TestSolveEx40(t *testing.T) {
	server := ex40Server{
		secret: []byte("Attack at dawn!"),
	}

	pub0, _, err := utils.GenRSAPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	pub1, _, err := utils.GenRSAPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := utils.GenRSAPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	cipher0 := new(big.Int).SetBytes(server.EncryptedSecret(pub0))
	cipher1 := new(big.Int).SetBytes(server.EncryptedSecret(pub1))
	cipher2 := new(big.Int).SetBytes(server.EncryptedSecret(pub2))

	moduliProductExcept0 := new(big.Int).Mul(pub1.N, pub2.N)
	moduliProductExcept1 := new(big.Int).Mul(pub0.N, pub2.N)
	moduliProductExcept2 := new(big.Int).Mul(pub0.N, pub1.N)

	r0 := new(big.Int).Mul(new(big.Int).Mul(cipher0, moduliProductExcept0), utils.InverseModulo(moduliProductExcept0, pub0.N))
	r1 := new(big.Int).Mul(new(big.Int).Mul(cipher1, moduliProductExcept1), utils.InverseModulo(moduliProductExcept1, pub1.N))
	r2 := new(big.Int).Mul(new(big.Int).Mul(cipher2, moduliProductExcept2), utils.InverseModulo(moduliProductExcept2, pub2.N))

	moduliProduct := new(big.Int).Mul(new(big.Int).Mul(pub0.N, pub1.N), pub2.N)

	result := new(big.Int)
	result.Add(result, r0)
	result.Add(result, r1)
	result.Add(result, r2)
	result.Mod(result, moduliProduct)

	cbrt := utils.CubeRoot(result)
	if !bytes.Equal(server.secret, cbrt.Bytes()) {
		t.Fatalf("mismatched decrypted plaintext: '%s' != '%s'", cbrt.Bytes(), server.secret)
	}
}
