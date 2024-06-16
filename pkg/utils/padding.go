package utils

import (
	"crypto"
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

// Ref: https://datatracker.ietf.org/doc/html/rfc3447#page-43
var DigestHeaders = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
}

func PadPKCS1(data []byte, length int, hash crypto.Hash) ([]byte, error) {
	if _, ok := DigestHeaders[hash]; !ok {
		return nil, fmt.Errorf("hash function %v not supported", hash)
	}

	paddedData := make([]byte, 0, length)
	paddedData = append(paddedData, data...)
	paddedData = append(paddedData, []byte{0x00, 0x01}...)

	// DATA || 00h || BT || PS || 00h || D
	psLen := max(8, length-hash.Size()-len(data)-3-len(DigestHeaders[hash])-hash.Size())
	ps := make([]byte, psLen)
	for i := 0; i < psLen; i++ {
		ps[i] = 0xFF
	}

	paddedData = append(paddedData, ps...)
	paddedData = append(paddedData, 0x00)
	paddedData = append(paddedData, DigestHeaders[hash]...)

	digest := hash.New()
	digest.Write(data)
	paddedData = digest.Sum(paddedData)

	return paddedData, nil
}
