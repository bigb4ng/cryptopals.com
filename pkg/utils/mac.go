package utils

import (
	"bytes"
	"crypto/sha1"

	"golang.org/x/crypto/md4"
)

func SignMessageSHA1(src, secret []byte) []byte {
	dst := make([]byte, 0, len(src)+sha1.Size+1)
	dst = append(dst, src...)
	dst = append(dst, '.')

	digest := sha1.New()
	digest.Write(secret)
	digest.Write(src)
	dst = digest.Sum(dst)

	return dst
}

func VerifyMessageSHA1(src, secret []byte) bool {
	digest := sha1.New()
	digest.Write(secret)
	digest.Write(src[:len(src)-sha1.Size-1])

	checksum := make([]byte, 0, sha1.Size)
	checksum = digest.Sum(checksum)

	return bytes.Equal(checksum, src[len(src)-sha1.Size:])
}

func SignMessageMD4(src, secret []byte) []byte {
	dst := make([]byte, 0, len(src)+md4.Size+1)
	dst = append(dst, src...)
	dst = append(dst, '.')

	digest := md4.New()
	digest.Write(secret)
	digest.Write(src)
	dst = digest.Sum(dst)

	return dst
}

func VerifyMessageMD4(src, secret []byte) bool {
	digest := md4.New()
	digest.Write(secret)
	digest.Write(src[:len(src)-md4.Size-1])

	checksum := make([]byte, 0, md4.Size)
	checksum = digest.Sum(checksum)

	return bytes.Equal(checksum, src[len(src)-md4.Size:])
}
