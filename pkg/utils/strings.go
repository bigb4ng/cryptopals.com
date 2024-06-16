package utils

import (
	"bytes"
	"fmt"
)

// RemoveChars will remove all unwanted chars in place and return the source array
func RemoveChars(src []byte, unwantedChars ...byte) []byte {
	j := 0
	for i := range src {
		if bytes.IndexByte(unwantedChars, src[i]) == -1 {
			src[j] = src[i]
			j++
		}
	}

	return src[:j]
}

func CalculateTextScore(src []byte) int {
	score := 0
	lowerBytes := bytes.ToLower(src)
	goodChars := []byte{'a', 'e', 'i', 'o', 'u', 'r', 's', 't', 'l', 'm', 'n', ' ', '.', ',', ';', ':', '\''}
	badChars := []byte{'@', '#', '$', '^', '*', '`', '\\', '{', '}', '|', '~', '>', '<', '-', '+', '=', '_', '[', ']', '"', '/', '@'}

	for i := range goodChars {
		score += bytes.Count(lowerBytes, []byte{goodChars[i]})
	}

	for i := range badChars {
		score -= bytes.Count(lowerBytes, []byte{badChars[i]}) * 2
	}

	return score
}

func PrintBlocks(src []byte, blockSize int) {
	fmt.Print("| ")
	for i := 0; i < len(src); i += blockSize {
		max := i + blockSize
		if max >= len(src) {
			max = len(src)
		}
		fmt.Printf("%s | ", HexEncode(src[i:max]))
	}
	fmt.Println()
}
