package set6

import (
	"bytes"
	"crypto/sha256"
	"main/pkg/utils"
	"math/big"
	"testing"
)

type ex41Server struct {
	pubKey   *utils.RSAPubKey
	privKey  *utils.RSAPrivKey
	messages map[string]bool
}

func NewEx41Server() (*ex41Server, error) {
	pub, priv, err := utils.GenRSAPair(2048)
	if err != nil {
		return nil, err
	}

	return &ex41Server{
		pubKey:   pub,
		privKey:  priv,
		messages: make(map[string]bool),
	}, nil
}

func (s *ex41Server) GetServerPubKey() *utils.RSAPubKey {
	return s.pubKey
}

func (s *ex41Server) Decrypt(blob []byte) []byte {
	hash := sha256.Sum256(blob)
	if s.messages[string(hash[:])] {
		return nil
	}

	s.messages[string(hash[:])] = true

	return utils.RSADecrypt(s.privKey, blob)
}

func TestSolveEx41(t *testing.T) {
	server, err := NewEx41Server()
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte("hello server!")
	pub := server.GetServerPubKey()
	cipher, err := utils.RSAEncrypt(pub, expected)
	if err != nil {
		t.Fatal(err)
	}

	decryptedMsg := server.Decrypt(cipher)
	if !bytes.Equal(decryptedMsg, expected) {
		t.Fatalf("server response mismatched original message: '%s' != '%s'", decryptedMsg, expected)
	}

	S := big.NewInt(2)
	C := new(big.Int).SetBytes(cipher)
	newCipher := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(S, pub.E, pub.N), C), pub.N)
	newPlain := new(big.Int).SetBytes(server.Decrypt(newCipher.Bytes()))
	recoveredPlain, _ := new(big.Int).DivMod(newPlain, S, pub.N)

	if !bytes.Equal(recoveredPlain.Bytes(), expected) {
		t.Fatalf("recovered plaintext mismatched original message: '%s' != '%s'", recoveredPlain.Bytes(), expected)
	}
}
