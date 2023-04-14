package utils

import (
	"errors"
	"fmt"
)

const encodeHex = "0123456789ABCDEF"

// HexDecode converts hex byte array to byte array
func HexDecode(src []byte) ([]byte, error) {
	if len(src)%2 != 0 {
		return nil, errors.New("fatal error: hex is incorrect length")
	}

	numberOfBytes := len(src) / 2
	dst := make([]byte, numberOfBytes)
	for i := 0; i < numberOfBytes; i++ {
		higherByte, err := hexLetterToNumber(src[i*2])
		if err != nil {
			return nil, err
		}
		lowerByte, err := hexLetterToNumber(src[i*2+1])
		if err != nil {
			return nil, err
		}

		dst[i] = (higherByte << 4) + lowerByte
	}
	return dst, nil
}

// HexEncode converts byte array to hex byte array
func HexEncode(src []byte) []byte {
	numberOfBytes := len(src) * 2
	dst := make([]byte, numberOfBytes)
	for i := 0; i < numberOfBytes; i += 2 {
		dst[i], dst[i+1] = numberToHexLetters(src[i/2])
	}
	return dst
}

func numberToHexLetters(num byte) (lower, higher byte) {
	higher = num % 16
	return toChar((num - higher) / 16), toChar(higher)
}

func hexLetterToNumber(ch byte) (byte, error) {
	ch = toUpper(ch)
	if !isUpperHexChar(ch) {
		return 0, fmt.Errorf("fatal error: invalid hex value: %s", string(ch))
	}
	if isNumber(ch) {
		return ch - '0', nil
	}
	return ch - 'A' + 10, nil
}

func toChar(ch byte) byte {
	return encodeHex[ch]
}

func isUpperHexChar(ch byte) bool {
	return ch >= '0' && ch <= 'F'
}
