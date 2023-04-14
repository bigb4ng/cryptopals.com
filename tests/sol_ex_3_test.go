package set1

import (
	"main/pkg/utils"
	"testing"
)

func TestSolveEx3(t *testing.T) {
	expected := "Cooking MC's like a pound of bacon"

	inp, _ := utils.HexDecode([]byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	results := utils.GuessSingleByteXor(inp)

	// Print top 10 solutions
	for i := 0; i < 5; i++ {
		t.Logf("key = %d, str = %s", results[i].Key, results[i].Plaintext)
		if string(results[i].Plaintext) == expected {
			return
		}
	}

	t.Fail()
}
