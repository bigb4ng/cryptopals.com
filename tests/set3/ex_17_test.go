package set3

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	_ "embed"
	"fmt"
	"main/pkg/utils"
	"testing"
)

//go:embed "assets/17.txt"
var randomStringsData []byte

type ex17oracle struct {
	key []byte
}

func NewEx17Oracle() (*ex17oracle, error) {
	var key = make([]byte, 16)
	var n, err = rand.Read(key)

	if err != nil || n != 16 {
		return nil, fmt.Errorf("failed obtaining random key: %v", err)
	}

	return &ex17oracle{key}, nil
}

func (o *ex17oracle) Encrypt() (dst []byte, iv []byte, err error) {
	src, err := o.selectRandomString()
	if err != nil {
		return nil, nil, err
	}

	iv = make([]byte, aes.BlockSize)
	n, err := rand.Read(iv)

	if err != nil || n != aes.BlockSize {
		return nil, nil, fmt.Errorf("failed obtaining random iv: %v", err)
	}

	dst, err = utils.EncryptCbcSlice(src, iv, o.key)
	if err != nil {
		return nil, nil, err
	}

	return dst, iv, err
}

func (o *ex17oracle) selectRandomString() ([]byte, error) {
	randomStrings := bytes.Split(randomStringsData, []byte("\n"))
	randomLine, err := utils.GetSecureRandomUint32(0, uint32(len(randomStrings)-1))
	if err != nil {
		return nil, err
	}

	return randomStrings[randomLine], nil
}

func (o *ex17oracle) CheckValidPadding(ciphertext []byte, iv []byte) bool {
	plaintext, err := utils.DecryptCbcSlice(ciphertext, iv, o.key)
	if err != nil {
		panic(err)
	}

	_, err = utils.UnpadPkcs7(plaintext, aes.BlockSize)
	return err == nil
}

func TestSolveEx17(t *testing.T) {
	oracle, err := NewEx17Oracle()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, iv, err := oracle.Encrypt()
	if err != nil {
		t.Fatal(err)
	}
	oracle.CheckValidPadding(ciphertext, iv)

	resultEncoded := make([]byte, len(ciphertext))
	var block []byte
	var prevBlock []byte
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block = ciphertext[i : i+aes.BlockSize]
		if i == 0 {
			prevBlock = iv
		} else {
			prevBlock = ciphertext[i-aes.BlockSize : i]
		}

		copy(resultEncoded[i:], utils.BreakCbcBlockPaddingOracle(block, prevBlock, oracle.CheckValidPadding))
	}

	resultEncoded, err = utils.UnpadPkcs7(resultEncoded, aes.BlockSize)
	if err != nil {
		t.Fatal(err)
	}

	result, err := utils.Base64Decode(resultEncoded)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%s", result)
}
