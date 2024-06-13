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

type Bob struct {
	key [20]byte
}

func (bob *Bob) InitKey(msg []*big.Int) (*big.Int, error) {
	p, g, A := msg[0], msg[1], msg[2]
	B, b, err := utils.NewDHPair(p, g)
	if err != nil {
		return nil, err
	}
	s := new(big.Int).Exp(A, b, p)

	bob.key = sha1.Sum(s.Bytes())

	return B, nil
}

func (bob *Bob) EchoMsg(msg []byte) ([]byte, error) {
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

type Eve struct {
	bob              Bob
	key              [20]byte
	InterceptedPlain []byte
}

func (eve *Eve) InitKey(msg []*big.Int) (*big.Int, error) {
	p, g, _ := msg[0], msg[1], msg[2]

	eve.bob = Bob{}
	_, err := eve.bob.InitKey([]*big.Int{p, g, p})
	if err != nil {
		return nil, err
	}

	eve.key = sha1.Sum(new(big.Int).Bytes())

	return p, nil
}

func (eve *Eve) EchoMsg(msg []byte) ([]byte, error) {
	plainMsg, err := utils.DecryptCBCSlice(msg[:len(msg)-aes.BlockSize], msg[len(msg)-aes.BlockSize:], eve.key[:16])
	if err != nil {
		return nil, err
	}

	eve.InterceptedPlain, err = utils.UnpadPKCS7(plainMsg, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return eve.bob.EchoMsg(msg)
}

type EchoFunc func(msg []byte) ([]byte, error)
type InitFunc func(msg []*big.Int) (*big.Int, error)

func GetEchoResponse(plaintext []byte, A, a *big.Int, echo EchoFunc, init InitFunc) ([]byte, error) {
	B, err := init([]*big.Int{&utils.DiffieHellmanP, &utils.DiffieHellmanG, A})
	if err != nil {
		return nil, err
	}

	var s big.Int
	s.Exp(B, a, &utils.DiffieHellmanP)

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

func TestSolveEx34(t *testing.T) {
	A, a, err := utils.NewDHPair(&utils.DiffieHellmanP, &utils.DiffieHellmanG)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("Keep rollin'")

	bob := Bob{}
	echoResponseBob, err := GetEchoResponse(plain, A, a, bob.EchoMsg, bob.InitKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plain, echoResponseBob) {
		t.Fatalf("mismatched plaintext from bob: %v != %v", plain, echoResponseBob)
	}

	eve := Eve{}
	echoResponseEve, err := GetEchoResponse(plain, A, a, eve.EchoMsg, eve.InitKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plain, echoResponseEve) {
		t.Fatalf("mismatched plaintext from bob trough eve: %v != %v", plain, echoResponseEve)
	}

	if !bytes.Equal(plain, eve.InterceptedPlain) {
		t.Fatalf("mismatched intercept from eve: %v != %v", plain, eve.InterceptedPlain)
	}
}
