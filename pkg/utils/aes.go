package utils

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
)

type OracleFunc func([]byte) ([]byte, error)
type CBCOracleFunc func([]byte, []byte) bool

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
func EncryptECBSlice(plaintext, key []byte) ([]byte, error) {
	plaintext = PadPKCS7(plaintext, aes.BlockSize)
	result := make([]byte, len(plaintext))

	numOfBlocks := len(plaintext) / aes.BlockSize

	for blockNumber := 0; blockNumber < numOfBlocks; blockNumber++ {
		plaintextBlock := plaintext[blockNumber*aes.BlockSize : (blockNumber+1)*aes.BlockSize]
		encryptedBlock, err := EncryptBlock(plaintextBlock, key)
		if err != nil {
			return nil, err
		}

		for j := range encryptedBlock {
			result[blockNumber*aes.BlockSize+j] = encryptedBlock[j]
		}
	}

	return result, nil
}

func DecryptECBSlice(src, key []byte) ([]byte, error) {
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

func DetectAESInECB(src []byte, threshold int) bool {
	if len(src)%aes.BlockSize != 0 {
		return false
	}

	for i := 0; i < len(src); i += aes.BlockSize {
		needle := src[i : i+aes.BlockSize]
		if bytes.Count(src, needle) >= threshold {
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

func EncryptCBCSlice(plaintext, iv, key []byte) ([]byte, error) {
	plaintext = PadPKCS7(plaintext, aes.BlockSize)
	result := make([]byte, len(plaintext))

	numOfBlocks := len(plaintext) / aes.BlockSize

	for blockNumber := 0; blockNumber < numOfBlocks; blockNumber++ {
		block := plaintext[blockNumber*aes.BlockSize : (blockNumber+1)*aes.BlockSize]
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

func CTRSlice(src []byte, key []byte, nonce uint64) ([]byte, error) {
	plainKey := make([]byte, aes.BlockSize)
	binary.LittleEndian.PutUint64(plainKey, nonce)

	for i := 0; i < len(src); i += aes.BlockSize {
		max := i + aes.BlockSize
		if max > len(src) {
			max = len(src)
		}

		binary.LittleEndian.PutUint64(plainKey[8:], uint64(i/aes.BlockSize))

		cipherKey, err := EncryptBlock(plainKey, key)
		if err != nil {
			return nil, err
		}

		copy(src[i:max], Xor(src[i:max], cipherKey))
	}

	return src, nil
}
