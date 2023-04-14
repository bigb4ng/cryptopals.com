package set1

import (
	"bytes"
	_ "embed"
	"main/pkg/utils"
	"testing"
)

//go:embed "assets/5.txt"
var ciphertext []byte

func TestSolveEx5(t *testing.T) {
	expected := []byte("0B3637272A2B2E63622C2E69692A23693A2A3C6324202D623D63343C2A26226324272765272A282B2F20430A652E2C652A3124333A653E2B2027630C692B20283165286326302E27282F")

	result := utils.HexEncode(utils.Xor(ciphertext, []byte("ICE")))

	if !bytes.Equal(result, expected) {
		t.Errorf("Expected: %v Got: %v", expected, result)
	}
}
