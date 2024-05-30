package set1

import (
	"bytes"
	_ "embed"
	"main/pkg/utils"
	"testing"
)

//go:embed "assets/6.txt"
var ciphertextEx6 []byte

func TestHammingDistance(t *testing.T) {
	expected := 37

	result, err := utils.SliceBitHammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))

	if err != nil {
		t.Fatal(err)
	}

	if result != expected {
		t.Fail()
	}
}

func TestSolveEx6(t *testing.T) {
	expected := []byte("Terminator X: Bring the noise")

	encodedCiphertext := utils.RemoveChars(ciphertextEx6, '\n')
	ciphertext, _ := utils.Base64Decode(encodedCiphertext)

	keySizeGuess := utils.GetGuessedKeySizes(ciphertext)
	for _, guess := range keySizeGuess[:3] {
		t.Logf("Trying to break with guessed keysize=%d (score: %f)\n", guess.KeySize, guess.Score)
		_, key := utils.BreakXor(ciphertext, guess.KeySize)

		if bytes.Equal(key, expected) {
			t.Logf("Found expected key: %s\n", string(key))
			return
		}
	}
	t.Fail()
}
