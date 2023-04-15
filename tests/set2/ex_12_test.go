package set2

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"fmt"
	"main/pkg/utils"
	"testing"
)

type ex12Oracle struct {
	key []byte
}

func NewEx12Oracle() (*ex12Oracle, error) {
	var key = make([]byte, 16)
	var n, err = rand.Read(key)

	if err != nil || n != 16 {
		return nil, fmt.Errorf("failed obtaining random key: %v", err)
	}

	return &ex12Oracle{key}, nil
}

//go:embed "assets/12.txt"
var suffixEx12 []byte

func (o *ex12Oracle) Encrypt(src []byte) ([]byte, error) {
	encodedSuffix := utils.RemoveChar(suffixEx12, '\n')
	suffix, _ := utils.Base64Decode(encodedSuffix)

	plaintext := make([]byte, len(src)+len(suffix))
	copy(plaintext[:len(src)], src)
	copy(plaintext[len(src):], suffix)

	return utils.EncryptEcbSlice(plaintext, o.key)
}

func TestSolveEx12(t *testing.T) {
	encodedSuffix := utils.RemoveChar(suffixEx12, '\n')
	expectedSuffix, _ := utils.Base64Decode(encodedSuffix)

	oracle, err := NewEx12Oracle()
	if err != nil {
		t.Fatal(err)
	}

	result, err := utils.BreakEcbSuffixOracle(oracle.Encrypt)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(expectedSuffix, result[:len(result)-1]) {
		t.Fatalf("result %v does not match expected suffix", result[:len(result)-1])
	}

}
