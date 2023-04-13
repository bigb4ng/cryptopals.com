package utils

import (
	"bytes"
)

func getCharProbabilityScore(ch byte) float32 {
	dict := []byte("ZQJXKVBPGYFMWCULDRHSNIOATE ")
	scoreTable := []float32{0.074, 0.095, 0.15, 0.15, 0.77, 0.98, 1.5, 1.9, 2, 2, 2.2, 2.4, 2.4, 2.8, 2.8, 4, 4.3, 6, 6.1, 6.3, 6.7, 7, 7.5, 8.2, 9.1, 13, 25}
	upper := toUpper(ch)
	dictIndex := FindByteIndexInArray(dict, upper)
	if dictIndex != -1 {
		return scoreTable[dictIndex]
	}

	if !bytes.Contains([]byte("&:-()?.,!'\""), []byte{ch}) {
		return -50.0
	}

	return 0.0
}

func ProbableTextScore(src []byte) (score float32) {
	for _, b := range src {
		score += getCharProbabilityScore(b)
	}

	impossibleCombos := []string{"JQ", "QG", "QK", "QY", "QZ", "WQ", "WZ"}
	for i := 0; i < len(src)-1; i += 1 {
		combo := []byte{toUpper(src[i]), toUpper(src[i+1])}
		for _, impossibleCombo := range impossibleCombos {
			if string(combo) == impossibleCombo {
				return 0
			}
		}
	}

	return score
}
