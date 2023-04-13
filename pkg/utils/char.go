package utils

func toUpper(ch byte) byte {
	if isLowerLetter(ch) {
		ch -= 'a' - 'A'
	}
	return ch
}

func isNumber(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func isLowerLetter(ch byte) bool {
	return ch >= 'a' && ch <= 'z'
}

func isUpperLetter(ch byte) bool {
	return ch >= 'A' && ch <= 'Z'
}

func isLetter(ch byte) bool {
	return isUpperLetter(ch) || isLowerLetter(ch)
}