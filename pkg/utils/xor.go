package utils

func Xor(src, key []byte) (dst []byte) {
	dst = make([]byte, len(src))
	for i, b := range src {
		dst[i] = b ^ key[i%len(key)]
	}

	return dst
}

// GuessSingleByteXor returns map of score to decoded array
func GuessSingleByteXor(src []byte, thresholdScore float32) (dst map[float32][]byte) {
	dst = make(map[float32][]byte)

	for i := 0; i < 256; i++ {
		ib := byte(i)
		attempt := Xor(src, []byte{ib})
		attemptScore := ProbableTextScore(attempt)
		if attemptScore > thresholdScore {
			dst[attemptScore] = attempt
		}

	}

	return dst
}
