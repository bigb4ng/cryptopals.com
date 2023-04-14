package set1

import (
	"bytes"
	"main/pkg/utils"
	"testing"
)

func TestSolveEx2(t *testing.T) {
	expected := []byte("746865206B696420646F6E277420706C6179")

	cyphertext, _ := utils.HexDecode([]byte("1c0111001f010100061a024b53535009181c"))
	key, _ := utils.HexDecode([]byte("686974207468652062756c6c277320657965"))

	result := utils.HexEncode(utils.Xor(cyphertext, key))

	if !bytes.Equal(expected, result) {
		t.Errorf("Expected: %s Got: %s", expected, result)
	}
}
