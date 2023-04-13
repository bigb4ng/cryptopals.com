package set1

import (
	"fmt"
	"main/pkg/utils"
)

func SolveEx3() {
	inp, _ := utils.HexDecode([]byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	sol := utils.GuessSingleByteXor(inp, 200.0)
	for k, v := range sol {
		fmt.Println(k, string(v))
	}
}
