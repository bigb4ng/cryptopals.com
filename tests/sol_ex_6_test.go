package set1

import (
	"bytes"
	_ "embed"
	"main/pkg/utils"
	"testing"
)

//go:embed "assets/6.txt"
var plaintextEx6 []byte

func TestHammingDistance(t *testing.T) {
	expected := 37

	result, err := utils.SliceBitHammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))

	if err != nil {
		t.Error(err)
	}

	if result != expected {
		t.Fail()
	}
}

func TestSolveEx6(t *testing.T) {
	expected := []byte("Terminator X: Bring the noise")

	var buf []byte
	for _, ch := range plaintextEx6 {
		if ch == '\n' {
			continue
		}

		buf = append(buf, ch)
	}

	dst, _ := utils.Base64Decode(buf)

	keySizeGuess := utils.GetGuessedKeySizes(dst)
	for _, guess := range keySizeGuess[:3] {
		t.Logf("Trying to break with guessed keysize=%d (score: %f)\n", guess.KeySize, guess.Score)
		_, key := utils.BreakXor(dst, guess.KeySize)

		if bytes.Equal(key, expected) {
			t.Logf("Found expected key: %s\n", string(key))
			return
		}
	}
	t.Fail()
}
