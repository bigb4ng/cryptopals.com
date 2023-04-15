package set1

import (
	_ "embed"
	"main/pkg/utils"
	"sort"
	"testing"
)

//go:embed "assets/4.txt"
var ciphersToGuess []byte

func TestSolveEx4(t *testing.T) {
	expected := "Now that the party is jumping\n"

	var sols []utils.SingleByteXorGuess

	var buf []byte
	for _, ch := range ciphersToGuess {
		if ch != '\n' {
			buf = append(buf, ch)
			continue
		}

		bufUnhex, err := utils.HexDecode(buf)
		if err != nil {
			t.Fatal(err)
		}
		sol := utils.GuessSingleByteXor(bufUnhex)
		sols = append(sols, sol...)
		buf = []byte{}
	}

	sort.Slice(sols, func(i, j int) bool {
		return sols[i].Score > sols[j].Score
	})

	for _, sol := range sols[:5] {
		t.Log(sol.Score, string(sol.Plaintext))
		if string(sol.Plaintext) == expected {
			return
		}
	}

	t.Fail()
}
