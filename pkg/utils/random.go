package utils

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// Get random uint32 within [min, max)
func GetSecureRandomUint32(min, max uint32) (result uint32, err error) {
	if max <= min {
		err := errors.New("max number is less or equal to min")
		return 0, err
	}

	numbersRange := max - min
	randomBytes := make([]byte, binary.Size(result))
	n, err := rand.Read(randomBytes)
	if n != binary.Size(result) || err != nil {
		return 0, err
	}

	result = binary.BigEndian.Uint32(randomBytes)
	result = result%uint32(numbersRange) + min

	return result, nil
}
