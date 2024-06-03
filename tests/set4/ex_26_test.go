package set3

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
	"main/pkg/utils"
	"testing"
)

type ex26Oracle struct {
	key   []byte
	nonce uint64
}

func NewEx26Oracle() (*ex26Oracle, error) {
	key := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, fmt.Errorf("failed obtaining random key: %v", err)
	}

	return &ex26Oracle{key, uint64(0)}, nil
}

func (o *ex26Oracle) Encrypt(src []byte) ([]byte, error) {
	prefix := []byte("comment1=cooking%20MCs;userdata=")
	suffix := []byte(";comment2=%20like%20a%20pound%20of%20bacon")

	src = utils.RemoveChars(src, ';', '=')

	plaintext := make([]byte, len(prefix)+len(src)+len(suffix))
	copy(plaintext[:len(prefix)], prefix)
	copy(plaintext[len(prefix):], src)
	copy(plaintext[len(prefix)+len(src):], suffix)

	o.nonce++
	ciphertext, err := utils.CtrSlice(plaintext, o.key, o.nonce)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(ciphertext)+8)
	binary.BigEndian.PutUint64(dst, o.nonce)
	copy(dst[8:], ciphertext)

	return dst, nil
}

func (o *ex26Oracle) IsAdmin(src []byte) bool {
	plaintext, err := utils.CtrSlice(src[8:], o.key, binary.BigEndian.Uint64(src[:8]))
	if err != nil {
		panic(err)
	}

	return bytes.Contains(plaintext, []byte(";admin=true;"))
}

func TestSolveEx26(t *testing.T) {
	oracle, err := NewEx26Oracle()
	if err != nil {
		t.Fatal(err)
	}

	cookiePrefix := []byte("comment1=cooking%20MCs;userdata=")

	plaintext := make([]byte, aes.BlockSize)

	ciphertext, err := oracle.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	keyStream := ciphertext[len(cookiePrefix)+8 : len(cookiePrefix)+aes.BlockSize+8]
	copy(ciphertext[len(cookiePrefix)+8:], utils.Xor(keyStream, []byte(";admin=true;")))

	if !oracle.IsAdmin(ciphertext) {
		t.Fatal("check for admin failed")
	}
}
