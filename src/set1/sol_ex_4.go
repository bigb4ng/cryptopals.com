package set1

import (
	_ "embed"
	"fmt"
	"main/pkg/utils"
)

//go:embed "assets/4.txt"
var ciphersToGuess []byte

func SolveEx4() {
	var buf []byte
	for _, ch := range ciphersToGuess {
		if ch == '\n' {
			bufUnhex, err := utils.HexDecode(buf)
			if err != nil {
				panic(err)
			}
			sol := utils.GuessSingleByteXor(bufUnhex, 200.0)
			for k, v := range sol {
				fmt.Println(k, string(v))
			}
			buf = []byte{}
			continue
		}

		buf = append(buf, ch)
	}
}
