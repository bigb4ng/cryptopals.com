package set1

import (
	"fmt"
	"main/pkg/utils"
)

func SolveEx2() {
	cyphertext, _ := utils.HexDecode([]byte("1c0111001f010100061a024b53535009181c"))
	key, _ := utils.HexDecode([]byte("686974207468652062756c6c277320657965"))

	fmt.Println(string(utils.HexEncode(utils.Xor(cyphertext, key))))
}
