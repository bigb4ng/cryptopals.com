package utils

import (
	"errors"
)

func BitHammingDistance(src, dst byte) (length int) {
	for src != 0 || dst != 0 {
		lowSrc := src & 0b1
		lowDst := dst & 0b1
		if lowSrc != lowDst {
			length++
		}
		src = src >> 1
		dst = dst >> 1
	}
	return length
}

func SliceBitHammingDistance(src, dst []byte) (length int, err error) {
	if len(src) != len(dst) {
		return 0, errors.New("array length doesn't match. cannot compute Hamming distance")
	}

	for i := range src {
		if src[i] != dst[i] {
			length += BitHammingDistance(src[i], dst[i])
		}
	}

	return length, nil
}

func BlockHammingDistance(src []byte, blockSize int) (float64, error) {
	iters := (len(src) / blockSize) - 1
	if iters == 0 {
		return -1, errors.New("slice is too short for the given block size")
	}

	distance := 0
	for i := 0; i < iters; i++ {
		first := src[i*blockSize : (i+1)*blockSize]
		second := src[(i+1)*blockSize : (i+2)*blockSize]
		blockDistance, err := SliceBitHammingDistance(first, second)
		if err != nil {
			return -1, err
		}
		distance += blockDistance
	}

	return float64(distance) / float64(blockSize) / float64(iters), nil
}
