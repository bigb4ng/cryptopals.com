package set2

import (
	"crypto/aes"
	"crypto/rand"
	_ "embed"
	"fmt"
	"main/pkg/utils"
	"testing"
)

func EncryptionECBOrCBCOracle(src []byte) ([]byte, uint32, error) {
	prefixBytesLength, err := utils.GetSecureRandomUint32(5, 11)
	if err != nil {
		return nil, 0, fmt.Errorf("failed reading random bytes for prefix: %v", err)
	}
	suffixBytesLength, err := utils.GetSecureRandomUint32(5, 11)
	if err != nil {
		return nil, 0, fmt.Errorf("failed reading random bytes for prefix: %v", err)
	}

	prefixBytes := make([]byte, prefixBytesLength)
	n, err := rand.Read(prefixBytes)
	if err != nil || n != int(prefixBytesLength) {
		return nil, 0, fmt.Errorf("failed reading random bytes for prefix: %v", err)
	}

	suffixBytes := make([]byte, suffixBytesLength)
	n, err = rand.Read(suffixBytes)
	if err != nil || n != int(suffixBytesLength) {
		return nil, 0, fmt.Errorf("failed reading random bytes for suffix: %v", err)
	}

	key := make([]byte, 16)
	n, err = rand.Read(key)
	if err != nil || n != int(16) {
		return nil, 0, fmt.Errorf("failed reading random bytes for suffix: %v", err)
	}

	finalPlaintext := make([]byte, int(prefixBytesLength)+len(src)+int(suffixBytesLength))
	copy(finalPlaintext[:prefixBytesLength], prefixBytes)
	copy(finalPlaintext[prefixBytesLength:len(finalPlaintext)-int(suffixBytesLength)], src)
	copy(finalPlaintext[len(finalPlaintext)-int(suffixBytesLength):], suffixBytes)

	var ciphertext []byte
	// 0 or 1
	modeOfOperation, err := utils.GetSecureRandomUint32(0, 2)
	if err != nil {
		return nil, 0, err
	}
	switch modeOfOperation {
	case 0:
		ciphertext, err = utils.EncryptECBSlice(finalPlaintext, key)
	case 1:
		iv := []byte("1234567890123456")
		ciphertext, err = utils.EncryptCBCSlice(finalPlaintext, iv, key)
	}

	if err != nil {
		return nil, 0, err
	}

	return ciphertext, modeOfOperation, nil
}

func TestSolveEx11(t *testing.T) {
	// prefix.ock|aes_block|aes_block|ae.suffix
	// since prefix + suffix is less than 1 block, 3 blocks are sufficient
	plaintext := make([]byte, aes.BlockSize*3)
	for i := range plaintext {
		plaintext[i] = 'A'
	}

	for i := 0; i < 10000; i++ {
		ciphertext, modeOfOperation, err := EncryptionECBOrCBCOracle(plaintext)
		if err != nil {
			t.Fatal(err)
		}

		switch modeOfOperation {
		case 0:
			if !utils.DetectAESInECB(ciphertext, 2) {
				t.Log(string(utils.HexEncode(ciphertext)))
				t.Fatal("ECB mode not detected")
			}
		case 1:
			if utils.DetectAESInECB(ciphertext, 2) {
				t.Log(string(utils.HexEncode(ciphertext)))
				t.Fatal("CBC mode detected as ECB")
			}
		}
	}
}
