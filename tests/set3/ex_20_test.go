package set3

import (
	"bytes"
	_ "embed"
	"main/pkg/utils"
	"strings"
	"testing"
)

//go:embed "assets/20.txt"
var examplePlaintextsEx20 []byte

func Ciphertexts() ([][]byte, error) {
	key := []byte("YELLOW SUBMARINE")
	plaintexts := bytes.Split(examplePlaintextsEx20, []byte{'\n'})
	ciphertexts := make([][]byte, len(plaintexts))

	for i, plainBase64 := range plaintexts {
		plaintext, err := utils.Base64Decode(plainBase64)
		if err != nil {
			return nil, err
		}

		ciphertext, err := utils.CTRSlice(plaintext, key, 0)
		if err != nil {
			return nil, err
		}

		ciphertexts[i] = ciphertext
	}

	return ciphertexts, nil
}

func TestSolveEx20(t *testing.T) {
	expected := "Cuz I came back to attack others"

	ciphertexts, err := Ciphertexts()
	if err != nil {
		t.Fatal(err)
	}

	maxRowLen := 0
	for _, ciphertext := range ciphertexts {
		if len(ciphertext) > maxRowLen {
			maxRowLen = len(ciphertext)
		}
	}

	xorKey := make([]byte, maxRowLen)
	for col := 0; col < maxRowLen; col++ {
		rowBytes := make([]byte, 0, len(ciphertexts))
		for row := range ciphertexts {
			if col < len(ciphertexts[row]) {
				rowBytes = append(rowBytes, ciphertexts[row][col])
			}
		}
		xorKey[col] = utils.GuessSingleByteXor(rowBytes)[0].Key
	}

	var sb strings.Builder
	for _, ciphertext := range ciphertexts {
		sb.Grow(len(ciphertext) + 1)
		for i := 0; i < len(ciphertext); i++ {
			sb.WriteByte(ciphertext[i] ^ xorKey[i])
		}
		sb.WriteByte('\n')
	}

	plaintext := sb.String()
	if !strings.Contains(plaintext, expected) {
		t.Fatalf("plaintext %v != expected %v", plaintext, expected)
	}
}
