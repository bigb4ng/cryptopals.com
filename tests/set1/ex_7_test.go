package set1

import (
	"bytes"
	_ "embed"
	"main/pkg/utils"
	"testing"
)

//go:embed "assets/7.txt"
var ciphertextEx7 []byte

func TestSolveEx7(t *testing.T) {
	expected := []byte("Play that funky music \n\x04\x04\x04\x04")

	key := []byte("YELLOW SUBMARINE")
	encodedCiphertext := utils.RemoveChars(ciphertextEx7, '\n')
	ciphertext, err := utils.Base64Decode(encodedCiphertext)
	if err != nil {
		t.Fatal(err)
	}

	result, err := utils.DecryptEcbSlice(ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.HasSuffix(result, expected) {
		t.Fatalf("string %v did not match expected prefix", result)
	}
}
