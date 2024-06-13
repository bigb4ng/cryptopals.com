package utils

import (
	"errors"
	"fmt"
)

func PadPKCS7(src []byte, blockSize int) []byte {
	paddingLength := blockSize - len(src)%blockSize

	dst := make([]byte, len(src)+paddingLength)
	copy(dst, src)

	for i := 0; i < paddingLength; i++ {
		dst[len(src)+i] = byte(paddingLength)
	}

	return dst
}

func UnpadPKCS7(data []byte, blockSize int) ([]byte, error) {
	if len(data)%blockSize != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padLen := int(data[len(data)-1])
	if padLen > blockSize || padLen == 0 {
		return nil, errors.New("padding is invalid")
	}
	// check padding
	pad := data[len(data)-padLen:]
	for i := 0; i < padLen; i++ {
		if pad[i] != byte(padLen) {
			return nil, errors.New("padding is invalid")
		}
	}
	return data[:len(data)-padLen], nil
}
