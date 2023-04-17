package set2

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	_ "embed"
	"fmt"
	"main/pkg/utils"
	"testing"
)

type ex16Oracle struct {
	key []byte
	iv  []byte
}

func NewEx16Oracle() (*ex16Oracle, error) {
	var key = make([]byte, 16)
	var n, err = rand.Read(key)

	if err != nil || n != 16 {
		return nil, fmt.Errorf("failed obtaining random key: %v", err)
	}

	var iv = make([]byte, 16)
	n, err = rand.Read(iv)

	if err != nil || n != 16 {
		return nil, fmt.Errorf("failed obtaining random iv: %v", err)
	}

	return &ex16Oracle{key, iv}, nil
}

func (o *ex16Oracle) Encrypt(src []byte) ([]byte, error) {
	prefix := []byte("comment1=cooking%20MCs;userdata=")
	suffix := []byte(";comment2=%20like%20a%20pound%20of%20bacon")

	src = utils.RemoveChar(src, ';')
	src = utils.RemoveChar(src, '=')

	plaintext := make([]byte, len(prefix)+len(src)+len(suffix))
	copy(plaintext[:len(prefix)], prefix)
	copy(plaintext[len(prefix):], src)
	copy(plaintext[len(prefix)+len(src):], suffix)

	return utils.EncryptCbcSlice(plaintext, o.iv, o.key)
}

func (o *ex16Oracle) IsAdmin(src []byte) bool {
	plaintext, err := utils.DecryptCbcSlice(src, o.iv, o.key)
	if err != nil {
		panic(err)
	}

	return bytes.Contains(plaintext, []byte(";admin=true;"))
}

func TestSolveEx16(t *testing.T) {
	oracle, err := NewEx16Oracle()
	if err != nil {
		t.Fatal(err)
	}

	cookiePrefix := "comment1=cooking%20MCs;userdata="
	cookieSuffix := ";comment2=%20like%20a%20pound%20of%20bacon"

	padding := aes.BlockSize - len(cookiePrefix)%aes.BlockSize
	plaintext := make([]byte, padding+aes.BlockSize)
	for i := range plaintext {
		plaintext[i] = 'A'
	}

	ciphertext, err := oracle.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}

	blockToFlipOffset := len(cookiePrefix) + len(plaintext) - aes.BlockSize
	cipherBlockToFlip := ciphertext[blockToFlipOffset : blockToFlipOffset+aes.BlockSize]

	// wanted plaintext ^ prev block cipher ^ next block plain
	copy(cipherBlockToFlip, utils.Xor([]byte(";admin=true;"), utils.Xor(cipherBlockToFlip, []byte(cookieSuffix[:aes.BlockSize]))))

	if !oracle.IsAdmin(ciphertext) {
		t.Fatal("check for admin failed")
	}
}
