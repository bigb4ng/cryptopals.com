package set2

import (
	"bytes"
	"main/pkg/utils"
	"testing"
)

func TestSolveEx1(t *testing.T) {
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	src := []byte("YELLOW SUBMARINE")
	paddingLength := 20

	result, _ := utils.Pkcs7Padding(src, paddingLength)

	if !bytes.Equal(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}
