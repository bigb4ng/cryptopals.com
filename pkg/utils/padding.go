package utils

import (
	"errors"
	"fmt"
)

func PadPkcs7(src []byte, dstLength int) ([]byte, error) {
	if len(src) > dstLength {
		return nil, errors.New("src len is longer than desired dst len")
	}

	dst := make([]byte, dstLength)
	copy(dst, src)
	paddingLength := dstLength - len(src)

	for i := 0; i < paddingLength; i++ {
		dst[len(src)+i] = byte(paddingLength)
	}

	return dst, nil
}
func UnpadPkcs7(data []byte, blockLen int) ([]byte, error) {
	if len(data)%blockLen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padLen := int(data[len(data)-1])
	if padLen > blockLen || padLen == 0 {
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
