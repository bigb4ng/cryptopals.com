package set1

import (
	"bytes"
	_ "embed"
	"main/pkg/utils"
	"testing"
)

//go:embed "assets/8.txt"
var ciphertextEx8 []byte

func TestSolveEx8(t *testing.T) {
	expected := 132

	for lineNum, encodedLine := range bytes.Split(ciphertextEx8, []byte("\n")) {
		line, err := utils.HexDecode(encodedLine)
		if err != nil {
			t.Error(err)
		}

		if utils.DetectAes(line) {
			if lineNum == expected {
				return
			} else {
				t.Errorf("false positive on line %d", lineNum)
			}
		}
	}

	t.Fail()
}