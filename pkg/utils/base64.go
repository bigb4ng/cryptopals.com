package utils

import (
	"encoding/binary"
	"fmt"
)

const paddingStd = byte('=')

var base64Alphabet = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

var paddingVal = FindByteIndexInArray(base64Alphabet, paddingStd)

func Base64Encode(src []byte) (dst []byte) {
	// number of blocks * 4
	dstLen := (len(src)/3 + BoolToInt(len(src)%3 != 0)) * 4
	dst = make([]byte, dstLen)

	j := 0
	i := 0
	for j < len(src)-len(src)%3 {
		dst[i] = base64Alphabet[src[j]>>2]
		dst[i+1] = base64Alphabet[src[j]<<6>>2|src[j+1]>>4]
		dst[i+2] = base64Alphabet[src[j+1]<<4>>2|src[j+2]>>6]
		dst[i+3] = base64Alphabet[src[j+2]<<2>>2]

		i += 4
		j += 3
	}

	charsLeft := len(src) - j
	switch charsLeft {
	case 2:
		dst[i] = base64Alphabet[src[j]>>2]
		dst[i+1] = base64Alphabet[src[j]<<6>>2|src[j+1]>>4]
		dst[i+2] = base64Alphabet[src[j+1]<<4>>2]
		dst[i+3] = paddingStd
	case 1:
		dst[i] = base64Alphabet[src[j]>>2]
		dst[i+1] = base64Alphabet[src[j]<<6>>2]
		dst[i+2] = paddingStd
		dst[i+3] = paddingStd
	}

	return dst
}

func Base64Decode(src []byte) (dst []byte, err error) {
	if len(src)%4 != 0 {
		return nil, fmt.Errorf("invalid base64 len: %d", len(src))
	}

	paddingLen := 0
	paddingLen += BoolToInt(src[len(src)-1] == paddingStd)
	paddingLen += BoolToInt(src[len(src)-2] == paddingStd)

	decodedLen := (len(src)/4)*3 - paddingLen

	dst = make([]byte, decodedLen+3)
	for i := 0; i < decodedLen; i += 3 {
		src_i := i / 3 * 4

		n1 := FindByteIndexInArray(base64Alphabet, src[src_i])
		n2 := FindByteIndexInArray(base64Alphabet, src[src_i+1])
		n3 := FindByteIndexInArray(base64Alphabet, src[src_i+2])
		n4 := FindByteIndexInArray(base64Alphabet, src[src_i+3])

		// last chunk
		if i+3 >= decodedLen {
			// zero out padding bytes
			if n3 == paddingVal {
				n3 = 0
			}
			if n4 == paddingVal {
				n4 = 0
			}
		}

		nb := uint32(n1)<<26 | uint32(n2)<<20 | uint32(n3)<<14 | uint32(n4)<<8

		binary.BigEndian.PutUint32(dst[i:], nb)
	}

	return dst[:decodedLen], nil
}
