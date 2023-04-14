package set1

import (
	"bytes"
	"main/pkg/utils"
	"testing"
)

func TestSolveEx1(t *testing.T) {
	expected := []byte("I'm killing your brain like a poisonous mushroom")

	result, err := utils.HexDecode([]byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(result, expected) {
		t.Errorf("Expected: %v Got: %v", string(expected), string(result))
	}
}
