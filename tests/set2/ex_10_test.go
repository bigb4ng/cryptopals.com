package set2

import (
	"bytes"
	_ "embed"
	"main/pkg/utils"
	"testing"
)

//go:embed "assets/10.txt"
var ciphertextEx10 []byte

func TestSolveEx10(t *testing.T) {
	expected := []byte("Play that funky music \n\x04\x04\x04\x04")

	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)

	encodedCiphertext := utils.RemoveChar(ciphertextEx10, '\n')
	ciphertext, err := utils.Base64Decode(encodedCiphertext)
	if err != nil {
		t.Error(err)
	}

	result, err := utils.DecryptCBCSlice(ciphertext, iv, key)
	if err != nil {
		t.Error(err)
	}

	if !bytes.HasSuffix(result, expected) {
		t.Errorf("string %v did not match expected prefix", result)
	}
}

func TestEncryptDecryptAesCBC(t *testing.T) {
	plaintext := []byte("Play that funky music \n\x04\x04\x04\x04")
	key := []byte("YELLOW SUBMARINE")
	iv := []byte("0123456789123456")

	ciphertext, err := utils.EncryptCBCSlice(plaintext, iv, key)
	if err != nil {
		t.Error(err)
	}

	result, err := utils.DecryptCBCSlice(ciphertext, iv, key)
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(result, plaintext) {
		t.Errorf("string %v did not match encrypted plaintext", result)
	}
}
