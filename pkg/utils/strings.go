package utils

import (
	"strings"
)

func CalculateTextScore(src []byte) float64 {
	score := 0
	goodChars := [12]string{"a", "e", "i", "o", "u", "r", "s", "t", "l", "m", "n", " "}

	for i := range goodChars {
		score += strings.Count(strings.ToLower(string(src)), goodChars[i])
	}

	return float64(score)
}
