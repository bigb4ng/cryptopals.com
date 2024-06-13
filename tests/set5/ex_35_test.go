package set5

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"main/pkg/utils"
	"math/big"
	"testing"
)

type BobEx35 struct {
	p, g *big.Int
	key  [20]byte
}

func (bob *BobEx35) Negotiate(p, g *big.Int) (*big.Int, *big.Int) {
	bob.p, bob.g = p, g
	return bob.p, bob.g
}

func (bob *BobEx35) RecvPubKey(A *big.Int) (*big.Int, error) {
	B, b, err := utils.NewDHPair(bob.p, bob.g)
	if err != nil {
		return nil, err
	}
	s := new(big.Int).Exp(A, b, bob.p)

	bob.key = sha1.Sum(s.Bytes())

	return B, nil

}

func (bob *BobEx35) EchoMsg(msg []byte) ([]byte, error) {
	msg, err := utils.DecryptCBCSlice(msg[:len(msg)-aes.BlockSize], msg[len(msg)-aes.BlockSize:], bob.key[:16])
	if err != nil {
		return nil, err
	}
	msgUnpad, err := utils.UnpadPKCS7(msg, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, 16)
	io.ReadFull(rand.Reader, iv)

	cipher, err := utils.EncryptCBCSlice(msgUnpad, iv, bob.key[:16])
	if err != nil {
		return nil, err
	}
	return append(cipher, iv...), nil
}

type EveEx35 struct {
	p, g             *big.Int
	bob              BobEx35
	key              [20]byte
	InterceptedPlain []byte
}

func (eve *EveEx35) Negotiate(p, g *big.Int) (*big.Int, *big.Int) {
	eve.p, eve.g = p, g

	eve.bob = BobEx35{}
	return eve.bob.Negotiate(eve.p, eve.g)
}

func (eve *EveEx35) RecvPubKey(A *big.Int) (*big.Int, error) {
	return eve.bob.RecvPubKey(eve.g)
}

func (eve *EveEx35) EchoMsg(msg []byte) ([]byte, error) {
	plainMsg, err := utils.DecryptCBCSlice(msg[:len(msg)-aes.BlockSize], msg[len(msg)-aes.BlockSize:], eve.key[:16])
	if err != nil {
		return nil, err
	}

	eve.InterceptedPlain, err = utils.UnpadPKCS7(plainMsg, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	response, err := eve.bob.EchoMsg(msg)
	if err != nil {
		return make([]byte, aes.BlockSize*2), nil
	}
	return response, nil
}

type SendPubFunc func(A *big.Int) (*big.Int, error)
type NegotiateFunc func(p, g *big.Int) (*big.Int, *big.Int)

func GetEchoResponseEx35(plaintext []byte, echo EchoFunc, negotiate NegotiateFunc, sendPub SendPubFunc) ([]byte, error) {
	p, g := negotiate(&utils.DiffieHellmanP, &utils.DiffieHellmanG)

	A, a, err := utils.NewDHPair(p, g)
	if err != nil {
		return nil, err
	}

	B, err := sendPub(A)
	if err != nil {
		return nil, err
	}

	var s big.Int
	s.Exp(B, a, p)

	key := sha1.Sum(s.Bytes())

	iv := make([]byte, 16)
	io.ReadFull(rand.Reader, iv)

	cipher, err := utils.EncryptCBCSlice(plaintext, iv, key[:16])
	if err != nil {
		return nil, err
	}
	cipher = append(cipher, iv...)

	echoMsg, err := echo(cipher)
	if err != nil {
		return nil, err
	}
	echoCipher, echoIv := echoMsg[:len(echoMsg)-aes.BlockSize], echoMsg[len(echoMsg)-aes.BlockSize:]
	echoPlain, err := utils.DecryptCBCSlice(echoCipher, echoIv, key[:16])
	if err != nil {
		return nil, err
	}

	echoPlainUnpad, err := utils.UnpadPKCS7(echoPlain, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return echoPlainUnpad, nil
}

func TestSolveEx35NoIntercept(t *testing.T) {
	plain := []byte("Keep rollin'")

	bob := BobEx35{}
	echoResponseBob, err := GetEchoResponseEx35(plain, bob.EchoMsg, bob.Negotiate, bob.RecvPubKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plain, echoResponseBob) {
		t.Fatalf("mismatched plaintext from bob: %v != %v", plain, echoResponseBob)
	}
}

func TestSolveEx35Part1(t *testing.T) {
	plain := []byte("Keep rollin'")

	eve := EveEx35{
		key: sha1.Sum([]byte{1}),
	}
	echoResponseEve, err := GetEchoResponseEx35(plain, eve.EchoMsg, func(p, g *big.Int) (*big.Int, *big.Int) { return eve.Negotiate(p, new(big.Int).SetInt64(1)) }, eve.RecvPubKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plain, echoResponseEve) {
		t.Fatalf("mismatched plaintext from bob trough evePart1: %v != %v", plain, echoResponseEve)
	}

	if !bytes.Equal(plain, eve.InterceptedPlain) {
		t.Fatalf("mismatched intercept from evePart1: %v != %v", plain, eve.InterceptedPlain)
	}
}

func TestSolveEx35Part2(t *testing.T) {
	plain := []byte("Keep rollin'")

	eve := EveEx35{
		key: sha1.Sum([]byte{}),
	}
	echoResponseEve, err := GetEchoResponseEx35(plain, eve.EchoMsg, func(p, g *big.Int) (*big.Int, *big.Int) { return eve.Negotiate(p, p) }, eve.RecvPubKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plain, echoResponseEve) {
		t.Fatalf("mismatched plaintext from bob trough evePart1: %v != %v", plain, echoResponseEve)
	}

	if !bytes.Equal(plain, eve.InterceptedPlain) {
		t.Fatalf("mismatched intercept from evePart1: %v != %v", plain, eve.InterceptedPlain)
	}
}

func TestSolveEx35Part3(t *testing.T) {
	plain := []byte("Hello!")

	eve := EveEx35{
		key: sha1.Sum([]byte{}),
	}

	// Unfortunately, even though we know what secret keys can be,
	// they can be mismatched between Alice and Bob
	_, _ = GetEchoResponseEx35(plain, func(msg []byte) ([]byte, error) {
		// Depending on evenness of a and b will produce s = 1 or s = p-1
		// this is due to tha fact that g = (p-1)mod(p) = (-1)mod(p) and
		// s = g ** (a * b) mod (p) = (-1) ** (a * b) mod (p).
		// Only odd powers of g will produce s = p-1, and odd powers are
		// less rare because only odd * odd = odd, so we try s = 1 first
		eve.key = sha1.Sum([]byte{1})
		echoMsg, err := eve.EchoMsg(msg)

		// Try to guess if we decoded correctly. padding may randomly be
		// correct for incorrectly decrypted string, so match ascii only
		if err != nil || bytes.ContainsFunc(eve.InterceptedPlain, func(r rune) bool { return byte(r) > 127 }) {
			eve.key = sha1.Sum(eve.g.Bytes())
			echoMsg, err = eve.EchoMsg(msg)
			if err != nil {
				return nil, err
			}
		}

		return echoMsg, nil
	}, func(p, g *big.Int) (*big.Int, *big.Int) {
		pMinus1 := new(big.Int).Sub(p, new(big.Int).SetInt64(1))

		return eve.Negotiate(p, pMinus1)
	}, eve.RecvPubKey)

	if !bytes.Equal(plain, eve.InterceptedPlain) {
		t.Fatalf("mismatched intercept from evePart1: %v != %v", plain, eve.InterceptedPlain)
	}
}
