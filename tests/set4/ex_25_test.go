package set3

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"fmt"
	"main/pkg/utils"
	"math"
	"testing"
)

//go:embed "assets/25.txt"
var ex25Data []byte

type ex25oracle struct {
	key        []byte
	plaintext  []byte
	Ciphertext []byte
}

func NewEx25Oracle(plaintext []byte) (*ex25oracle, error) {
	oracle := &ex25oracle{plaintext: bytes.Clone(plaintext)}

	nonce, err := utils.GetSecureRandomUint32(0, math.MaxUint32)
	if err != nil {
		return nil, fmt.Errorf("failed getting a random nonce: %v", err)
	}

	oracle.key = make([]byte, 16)
	n, err := rand.Read(oracle.key)
	if err != nil || n != 16 {
		return nil, fmt.Errorf("failed obtaining random key: %v", err)
	}

	oracle.Ciphertext, err = utils.CtrSlice(plaintext, oracle.key, uint64(nonce))
	if err != nil {
		return nil, fmt.Errorf("failed encrypting: %v", err)
	}

	return oracle, nil
}

func (o *ex25oracle) Edit(offset int, newPlaintext []byte) {
	keyStream := utils.Xor(o.Ciphertext[offset:offset+len(newPlaintext)], o.plaintext[offset:offset+len(newPlaintext)])
	copy(o.Ciphertext[offset:offset+len(newPlaintext)], utils.Xor(newPlaintext, keyStream))
}

func TestSolveEx25(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")

	encodedCiphertext := utils.RemoveChars(ex25Data, '\n')
	ciphertext25, err := utils.Base64Decode(encodedCiphertext)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := utils.DecryptEcbSlice(ciphertext25, key)
	if err != nil {
		t.Fatal(err)
	}

	oracle, err := NewEx25Oracle(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := bytes.Clone(oracle.Ciphertext)
	oracle.Edit(0, make([]byte, len(ciphertext)))

	recoveredPlaintext := utils.Xor(oracle.Ciphertext, ciphertext)

	if !bytes.Equal(recoveredPlaintext, oracle.plaintext) {
		t.Fatal("Recovered plaintext does not match original plaintext")
	}
}
