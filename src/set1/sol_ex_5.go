package set1

import (
	_ "embed"
	"fmt"
	"main/pkg/utils"
	"strings"
)

//go:embed "assets/5.txt"
var plaintext []byte

func SolveEx5() {
	fmt.Println(strings.ToLower(string(utils.HexEncode(utils.Xor(plaintext, []byte("ICE"))))))
}
