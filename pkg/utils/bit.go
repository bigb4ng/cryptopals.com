package utils

import "fmt"

func bitDistance(src, dst byte) (length int) {
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

func BitHammingDistance(src, dst []byte) (length int, err error) {
	if len(src) != len(dst) {
		return 0, fmt.Errorf("array length doesn't match. cannot compute Hamming distance")
	}

	for i := range src {
		if src[i] != dst[i] {
			length += bitDistance(src[i], dst[i])
		}
	}

	return length, nil
}

func BlockHammingDistance(src []byte, blockSize int) float64 {
	if len(src) < (blockSize * 4) {
		return -1
	}

	iters := (len(src) / blockSize) - 1

	distance := 0
	for i := 0; i < iters; i++ {
		first := src[i*blockSize : (i+1)*blockSize]
		second := src[(i+1)*blockSize : (i+2)*blockSize]
		blockDistance, _ := BitHammingDistance(first, second)
		distance += blockDistance
	}

	return float64(distance) / float64(blockSize) / float64(iters)
}
