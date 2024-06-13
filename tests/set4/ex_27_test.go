package set4

import (
	"bytes"
	"crypto/aes"
	_ "embed"
	"fmt"
	"main/pkg/utils"
	"strings"
	"testing"
)

type ex27Oracle struct {
	key []byte
	iv  []byte
}

func NewEx27Oracle(key []byte) (*ex27Oracle, error) {
	return &ex27Oracle{key, key}, nil
}

func (o *ex27Oracle) Encrypt(src []byte) ([]byte, error) {
	prefix := []byte("comment1=cooking%20MCs;userdata=")
	suffix := []byte(";comment2=%20like%20a%20pound%20of%20bacon")

	src = utils.RemoveChars(src, ';', '=')
	plaintext := make([]byte, len(prefix)+len(src)+len(suffix))
	copy(plaintext[:len(prefix)], prefix)
	copy(plaintext[len(prefix):], src)
	copy(plaintext[len(prefix)+len(src):], suffix)

	return utils.EncryptCBCSlice(plaintext, o.iv, o.key)
}

func (o *ex27Oracle) IsAdmin(src []byte) (bool, error) {
	plaintext, err := utils.DecryptCBCSlice(src, o.iv, o.key)
	if err != nil {
		panic(err)
	}

	if bytes.ContainsFunc(plaintext, func(b rune) bool { return b > 127 }) {
		return false, fmt.Errorf("invalid character: %s", plaintext)
	}

	return bytes.Contains(plaintext, []byte(";admin=true;")), nil
}

func TestSolveEx27(t *testing.T) {
	expectedKey := []byte("YELLOW SUBMARINE")

	oracle, err := NewEx27Oracle(expectedKey)
	if err != nil {
		t.Fatal(err)
	}

	cookiePrefix := "comment1=cooking%20MCs;userdata="

	padding := aes.BlockSize - len(cookiePrefix)%aes.BlockSize
	plaintext := make([]byte, padding+aes.BlockSize)
	for i := range plaintext {
		plaintext[i] = 'A'
	}

	ciphertext, err := oracle.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}

	copy(ciphertext[aes.BlockSize:aes.BlockSize*2], make([]byte, aes.BlockSize))
	copy(ciphertext[aes.BlockSize*2:aes.BlockSize*3], ciphertext[0:aes.BlockSize])

	_, err = oracle.IsAdmin(ciphertext)
	recoveredPlain := strings.TrimPrefix(fmt.Sprint(err), "invalid character: ")
	key := utils.Xor([]byte(recoveredPlain[0:aes.BlockSize]), []byte(recoveredPlain[aes.BlockSize*2:aes.BlockSize*3]))

	if !bytes.Equal(expectedKey, key) {
		t.Fatalf("recovered key does not match expected: %s != %s", key, expectedKey)
	}
}
