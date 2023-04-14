package set1

import (
	_ "embed"
	"main/pkg/utils"
	"strings"
	"testing"
)

//go:embed "assets/7.txt"
var ciphertextEx7 []byte

func TestSolveEx7(t *testing.T) {
	// expected := []byte("Terminator X: Bring the noise")

	key := []byte("YELLOW SUBMARINE")
	encodedCiphertext := utils.RemoveChar(ciphertextEx7, '\n')
	ciphertext, err := utils.Base64Decode(encodedCiphertext)
	if err != nil {
		t.Error(err)
	}

	t.Log(len(ciphertext))

	result, err := utils.DecryptSlice(ciphertext, key)
	if err != nil {
		t.Error(err)
	}

	if !strings.HasPrefix(string(result), "Play that funky music") {
		t.Errorf("string %s did not match expected result", result)
	}
}
