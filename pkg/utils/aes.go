package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
)

type OracleFunc func([]byte) ([]byte, error)

func EncryptBlock(src []byte, key []byte) ([]byte, error) {
	if len(src) != aes.BlockSize {
		return nil, errors.New("invalid block size")
	}

	encryptor, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))
	encryptor.Encrypt(dst, src)

	return dst, nil
}

func DecryptBlock(src []byte, key []byte) ([]byte, error) {
	if len(src) != aes.BlockSize {
		return nil, errors.New("invalid block size")
	}

	encryptor, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(src))
	encryptor.Decrypt(dst, src)

	return dst, nil

}
func EncryptEcbSlice(src, key []byte) ([]byte, error) {
	src, err := Pkcs7Padding(src, len(src)-len(src)%aes.BlockSize+boolToInt(len(src)%aes.BlockSize > 0)*aes.BlockSize)
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(src))

	numOfBlocks := len(src) / aes.BlockSize

	for blockNumber := 0; blockNumber < numOfBlocks; blockNumber++ {
		block := src[blockNumber*aes.BlockSize : (blockNumber+1)*aes.BlockSize]
		decryptedBlock, err := EncryptBlock(block, key)
		if err != nil {
			return nil, err
		}

		for j := range decryptedBlock {
			result[blockNumber*aes.BlockSize+j] = decryptedBlock[j]
		}
	}

	return result, nil
}

func DecryptEcbSlice(src, key []byte) ([]byte, error) {
	if len(src)%aes.BlockSize != 0 {
		return nil, errors.New("invalid slice size")
	}
	result := make([]byte, len(src))

	numOfBlocks := len(src) / aes.BlockSize

	for blockNumber := 0; blockNumber < numOfBlocks; blockNumber++ {
		block := src[blockNumber*aes.BlockSize : (blockNumber+1)*aes.BlockSize]
		decryptedBlock, err := DecryptBlock(block, key)
		if err != nil {
			return nil, err
		}

		for j := range decryptedBlock {
			result[blockNumber*aes.BlockSize+j] = decryptedBlock[j]
		}
	}

	return result, nil
}

func DetectEcbAes(src []byte) bool {
	if len(src)%aes.BlockSize != 0 {
		return false
	}

	srcBlocks := make([][]byte, len(src)/aes.BlockSize)

	for i := 0; i < len(srcBlocks); i++ {
		lower := i * aes.BlockSize
		higher := (i + 1) * aes.BlockSize

		var hay []byte
		hay = append(hay, src[:lower]...)
		hay = append(hay, src[higher:]...)

		needle := src[lower:higher]
		if bytes.Contains(hay, needle) {
			return true
		}
	}

	return false
}

func DecryptCbcSlice(src, iv, key []byte) ([]byte, error) {
	if len(src)%aes.BlockSize != 0 {
		return nil, errors.New("invalid slice size")
	}
	result := make([]byte, len(src))

	numOfBlocks := len(src) / aes.BlockSize

	for blockNumber := 0; blockNumber < numOfBlocks; blockNumber++ {
		block := src[blockNumber*aes.BlockSize : (blockNumber+1)*aes.BlockSize]
		decryptedBlock, err := DecryptBlock(block, key)
		if err != nil {
			return nil, err
		}

		xoredBlock := Xor(decryptedBlock, iv)
		iv = block

		for j := range xoredBlock {
			result[blockNumber*aes.BlockSize+j] = xoredBlock[j]
		}
	}

	return result, nil
}

func EncryptCbcSlice(src, iv, key []byte) ([]byte, error) {
	src, err := Pkcs7Padding(src, len(src)-len(src)%aes.BlockSize+boolToInt(len(src)%aes.BlockSize > 0)*aes.BlockSize)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(src))

	numOfBlocks := len(src) / aes.BlockSize

	for blockNumber := 0; blockNumber < numOfBlocks; blockNumber++ {
		block := src[blockNumber*aes.BlockSize : (blockNumber+1)*aes.BlockSize]
		xoredBlock := Xor(block, iv)
		encryptedBlock, err := EncryptBlock(xoredBlock, key)
		if err != nil {
			return nil, err
		}

		iv = encryptedBlock

		for j := range encryptedBlock {
			result[blockNumber*aes.BlockSize+j] = encryptedBlock[j]
		}
	}

	return result, nil
}

func EncryptionEcbOrCbcOracle(src []byte) ([]byte, uint32, error) {
	prefixBytesLength, err := GetSecureRandomUint32(5, 11)
	if err != nil {
		return nil, 0, fmt.Errorf("failed reading random bytes for prefix: %v", err)
	}
	suffixBytesLength, err := GetSecureRandomUint32(5, 11)
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
	modeOfOperation, err := GetSecureRandomUint32(0, 2)
	if err != nil {
		return nil, 0, err
	}
	switch modeOfOperation {
	case 0:
		ciphertext, err = EncryptEcbSlice(finalPlaintext, key)
	case 1:
		iv := []byte("1234567890123456")
		ciphertext, err = EncryptCbcSlice(finalPlaintext, iv, key)
	}

	if err != nil {
		return nil, 0, err
	}

	return ciphertext, modeOfOperation, nil
}

func BreakEcbSuffixOracle(oracleFunc OracleFunc) ([]byte, error) {
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

	if !DetectEcbAes(ciphertext) {
		return nil, errors.New("given oracle is not consistant with ECB mode")
	}

	plaintext = make([]byte, blockSize*2)
	// for i := range plaintext {
	// 	plaintext[i] = 'A'
	// }

	// ....|....|....|
	// AAA*|AAA|SECRET
	// AAS*|AA|SECRET
	// brute first block
	var decryptedSuffix []byte
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

			if DetectEcbAes(HexEncode(ciphertext)) {
				decryptedSuffix = append(decryptedSuffix, byte(j))
				foundMatch = true
				break
			}
		}
	}

	return decryptedSuffix, nil
}
