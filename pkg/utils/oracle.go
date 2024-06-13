package utils

import (
	"crypto/aes"
	"errors"
)

func BreakECBSuffixOracle(oracleFunc OracleFunc) ([]byte, error) {
	plaintext := []byte{}
	shortestCipherLen, err := oracleFunc(plaintext)
	if err != nil {
		return nil, err
	}

	blockSize := 0
	for {
		plaintext = append(plaintext, 'A')
		tempCipher, err := oracleFunc(plaintext)
		if err != nil {
			return nil, err
		}
		if len(shortestCipherLen) < len(tempCipher) {
			blockSize = len(tempCipher) - len(shortestCipherLen)
			break
		}
	}

	if blockSize != aes.BlockSize {
		return nil, errors.New("detected block size is not consistant with AES")
	}

	plaintext = make([]byte, aes.BlockSize*3)
	for i := range plaintext {
		plaintext[i] = 'A'
	}
	ciphertext, err := oracleFunc(plaintext)
	if err != nil {
		return nil, err
	}

	if !DetectAESInECB(ciphertext, 2) {
		return nil, errors.New("given oracle is not consistant with ECB mode")
	}

	// ....|....|....|
	// AAA*|AAA|SECRET
	// AAS*|AA|SECRET
	// brute first block
	var decryptedSuffix []byte
	plaintext = make([]byte, blockSize*2)
	foundMatch := false
	for i := 0; foundMatch || i == 0; i++ {
		foundMatch = false
		copy(plaintext, plaintext[1:])
		for j := 0; j <= 255; j++ {
			plaintext[blockSize-1] = byte(j)

			ciphertext, err := oracleFunc(plaintext[:blockSize*2-1-i%blockSize])
			if err != nil {
				return nil, err
			}

			if DetectAESInECB(ciphertext, 2) {
				decryptedSuffix = append(decryptedSuffix, byte(j))
				foundMatch = true
				break
			}
		}
	}

	return decryptedSuffix, nil
}

func BreakCBCBlockPaddingOracle(ciphertext []byte, iv []byte, checkPadding CBCOracleFunc) []byte {
	result := make([]byte, 16)

	origIv := make([]byte, len(iv))
	copy(origIv, iv)

	for i := range iv {
		for j := 0; j < 256; j++ {
			iv[aes.BlockSize-1-i] = byte(j)

			if checkPadding(ciphertext, iv) {
				break
			}
		}

		result[aes.BlockSize-1-i] = iv[aes.BlockSize-1-i] ^ origIv[aes.BlockSize-1-i] ^ byte(i+1)

		// setup padding for next
		for j := aes.BlockSize - 1 - i; j < aes.BlockSize; j++ {
			iv[j] = iv[j] ^ byte(i+1) ^ byte(i+2)
		}
	}

	return result
}
