package utils

// FindByteIndexInArray returns index or -1 if key is not found
func FindByteIndexInArray(arr []byte, ch byte) (index int) {
	for i := range arr {
		if arr[i] == ch {
			return i
		}
	}
	return -1
}

func LastFullBlock[S ~[]E, E any](src S, blockSize int) []E {
	return src[len(src)-len(src)%blockSize-blockSize : len(src)-len(src)%blockSize]
}
