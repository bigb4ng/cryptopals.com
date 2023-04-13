package utils

const encodeBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
const paddingStd = byte('=')

func Base64Encode(src []byte) (dst []byte) {
	// number of blocks * 4
	dstLen := (len(src)/3 + boolToInt(len(src)%3 > 0)) * 4
	paddedChars := 0
	switch len(src) % 3 {
	case 1:
		paddedChars = 2
	case 2:
		paddedChars = 1
	}

	dst = make([]byte, dstLen)

	j := 0
	for i := 0; i < len(dst); i += 4 {
		dst[i] = encodeBase64[src[j]>>2]
		dst[i+1] = encodeBase64[src[j]<<6>>2|src[j+1]>>4]

		if i+4 < len(dst) || paddedChars == 0 {
			dst[i+2] = encodeBase64[src[j+1]<<4>>2|src[j+2]>>6]
			dst[i+3] = encodeBase64[src[j+2]<<2>>2]
		} else {
			// need to set padding
			dst[i+3] = paddingStd
			if paddedChars == 2 {
				dst[i+2] = paddingStd
			} else {
				dst[i+2] = encodeBase64[src[j+1]<<4>>2|src[j+2]>>6]
			}
		}

		j += 3
	}

	return dst
}
