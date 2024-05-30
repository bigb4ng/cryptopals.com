package utils

import (
	"bytes"
	"fmt"
)

func RemoveChars(src []byte, unwantedChar ...byte) (dst []byte) {
	return bytes.ReplaceAll(src, unwantedChar, []byte{})
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
