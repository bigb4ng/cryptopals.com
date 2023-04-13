package set1

import (
	"fmt"
	"main/pkg/utils"
)

func SolveEx1() {
	inp, _ := utils.HexDecode([]byte("49276d206696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))

	fmt.Println(string(utils.Base64Encode(inp)))
}
