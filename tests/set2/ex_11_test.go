package set2

import (
	"crypto/aes"
	_ "embed"
	"main/pkg/utils"
	"testing"
)

func TestSolveEx11(t *testing.T) {
	// prefix.ock|aes_block|aes_block|ae.suffix
	// since prefix + suffix is less than 1 block, 3 blocks are sufficient
	plaintext := make([]byte, aes.BlockSize*3)
	for i := range plaintext {
		plaintext[i] = 'A'
	}

	for i := 0; i < 10000; i++ {
		ciphertext, modeOfOperation, err := utils.EncryptionEcbOrCbcOracle(plaintext)
		if err != nil {
			t.Fatal(err)
		}

		switch modeOfOperation {
		case 0:
			if !utils.DetectEcbAes(ciphertext, 2) {
				t.Log(string(utils.HexEncode(ciphertext)))
				t.Fatal("ECB mode not detected")
			}
		case 1:
			if utils.DetectEcbAes(ciphertext, 2) {
				t.Log(string(utils.HexEncode(ciphertext)))
				t.Fatal("CBC mode detected as ECB")
			}
		}
	}
}
