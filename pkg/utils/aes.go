package utils

import (
	"bytes"
	"crypto/aes"
	"errors"
)

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

func DecryptSlice(src, key []byte) ([]byte, error) {
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

func DetectAes(src []byte) bool {
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

func DecryptCBCSlice(src, iv, key []byte) ([]byte, error) {
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

func EncryptCBCSlice(src, iv, key []byte) ([]byte, error) {
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
