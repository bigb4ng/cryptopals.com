package utils

import (
	"fmt"
	"strings"
)

func RemoveChar(src []byte, unwantedChar byte) (dst []byte) {
	for _, ch := range src {
		if ch == unwantedChar {
			continue
		}

		dst = append(dst, ch)
	}

	return dst
}

func CalculateTextScore(src []byte) float64 {
	score := 0
	goodChars := [12]string{"a", "e", "i", "o", "u", "r", "s", "t", "l", "m", "n", " "}

	for i := range goodChars {
		score += strings.Count(strings.ToLower(string(src)), goodChars[i])
	}

	return float64(score)
}

func PrintBlocks(src []byte, blockSize int) {
	fmt.Print("| ")
	for i := 0; i < len(src); i += blockSize {
		max := i + blockSize
		if max >= len(src) {
			max = len(src) - 1
		}
		fmt.Printf("%s | ", HexEncode(src[i:max]))
	}
	fmt.Println()
}
