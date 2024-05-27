package utils

import (
	"sort"
)

func Xor(src, key []byte) (dst []byte) {
	dst = make([]byte, len(src))
	for i, b := range src {
		dst[i] = b ^ key[i%len(key)]
	}

	return dst
}

type SingleByteXorGuess struct {
	Plaintext []byte
	Key       byte
	Score     int
}

// GuessSingleByteXor returns map of score to decoded array
func GuessSingleByteXor(src []byte) (dst []SingleByteXorGuess) {
	dst = make([]SingleByteXorGuess, 256)

	for i := 0; i < 256; i++ {
		ib := byte(i)

		attempt := Xor(src, []byte{ib})
		attemptScore := CalculateTextScore(attempt)

		dst[i] = SingleByteXorGuess{attempt, ib, attemptScore}
	}

	sort.Slice(dst, func(i, j int) bool {
		return dst[i].Score > dst[j].Score
	})

	return dst
}

type KeySizeGuess struct {
	KeySize int
	Score   float64
}

func GetGuessedKeySizes(src []byte) []KeySizeGuess {
	minGuess := 2
	normalizedDistance := make([]KeySizeGuess, 40) // guess to distance

	for guess := 0; guess < 40; guess++ {
		if guess < minGuess {
			normalizedDistance[guess] = KeySizeGuess{guess, 0xFFFFFFFF}
			continue
		}
		dist, err := BlockHammingDistance(src, guess)
		if err != nil {
			normalizedDistance[guess] = KeySizeGuess{guess, 0xFFFFFFFF}
			continue
		}
		normalizedDistance[guess] = KeySizeGuess{guess, dist}
	}

	sort.Slice(normalizedDistance, func(i, j int) bool {
		return normalizedDistance[i].Score < normalizedDistance[j].Score
	})

	return normalizedDistance
}

func BreakXor(src []byte, keySize int) (result []byte, key []byte) {
	result = make([]byte, len(src))
	key = make([]byte, keySize)

	rows := make([][]byte, keySize)
	for i := range rows {
		rows[i] = make([]byte, (len(src)/keySize)+1)
	}
	for i := range src {
		rows[i%keySize][i/keySize] = src[i]
	}

	maxScoreStringRows := make([][]byte, keySize)
	for i, row := range rows {
		sols := GuessSingleByteXor(row)
		maxScoreStringRows[i] = sols[0].Plaintext
		key[i] = sols[0].Key
	}

	for i := range result {
		result[i] = maxScoreStringRows[i%keySize][i/keySize]
	}

	return result, key
}
