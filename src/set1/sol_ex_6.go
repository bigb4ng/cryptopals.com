package set1

import (
	_ "embed"
	"fmt"
	"main/pkg/utils"
)

//go:embed "assets/6.txt"
var plaintextEx6 []byte

func SolveEx6() {
	var buf []byte
	for _, ch := range plaintextEx6 {
		if ch == '\n' {
			continue
		}

		buf = append(buf, ch)
	}
	buf = utils.Base64Decode(buf)

	keySizeGuess := utils.GuessKeySize(buf)
	fmt.Println(string(utils.BreakXor(buf, keySizeGuess)))
}
