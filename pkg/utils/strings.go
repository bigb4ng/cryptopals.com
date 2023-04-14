package utils

import (
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
