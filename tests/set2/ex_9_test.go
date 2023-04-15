package set2

import (
	"bytes"
	"main/pkg/utils"
	"testing"
)

func TestSolveEx9(t *testing.T) {
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	src := []byte("YELLOW SUBMARINE")
	paddingLength := 20

	result, err := utils.Pkcs7Padding(src, paddingLength)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}