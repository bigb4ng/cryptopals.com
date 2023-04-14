package utils

import (
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
