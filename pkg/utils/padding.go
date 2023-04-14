package utils

import "errors"

func Pkcs7Padding(src []byte, dstLength int) ([]byte, error) {
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
