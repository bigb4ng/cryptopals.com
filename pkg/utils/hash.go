package utils

import (
	"crypto/sha1"
	"encoding/binary"
	"math/bits"
)

const (
	_K0 = 0x5A827999
	_K1 = 0x6ED9EBA1
	_K2 = 0x8F1BBCDC
	_K3 = 0xCA62C1D6
)

func Sha1PadMessage(messageBlock []byte, prevLen int) []byte {
	paddedBlock := make([]byte, sha1.BlockSize)

	copy(paddedBlock, messageBlock)
	paddedBlock[len(messageBlock)] = 0x80

	lenInBits := uint64(len(messageBlock)+prevLen) << 3
	binary.BigEndian.PutUint64(paddedBlock[len(paddedBlock)-8:], lenInBits)

	return paddedBlock
}

func Sha1ComputeBlock(p []byte, h0, h1, h2, h3, h4 uint32) [sha1.Size]byte {
	a, b, c, d, e := h0, h1, h2, h3, h4

	var w [16]uint32
	for i := 0; i < 16; i++ {
		j := i * 4
		w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
	}

	i := 0
	for ; i < 16; i++ {
		f := b&c | (^b)&d
		t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K0
		a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
	}
	for ; i < 20; i++ {
		tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
		w[i&0xf] = bits.RotateLeft32(tmp, 1)

		f := b&c | (^b)&d
		t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K0
		a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
	}
	for ; i < 40; i++ {
		tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
		w[i&0xf] = bits.RotateLeft32(tmp, 1)
		f := b ^ c ^ d
		t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K1
		a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
	}
	for ; i < 60; i++ {
		tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
		w[i&0xf] = bits.RotateLeft32(tmp, 1)
		f := ((b | c) & d) | (b & c)
		t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K2
		a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
	}
	for ; i < 80; i++ {
		tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf]
		w[i&0xf] = bits.RotateLeft32(tmp, 1)
		f := b ^ c ^ d
		t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + _K3
		a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
	}

	h0 += a
	h1 += b
	h2 += c
	h3 += d
	h4 += e

	var out [sha1.Size]byte
	binary.BigEndian.PutUint32(out[0:], h0)
	binary.BigEndian.PutUint32(out[4:], h1)
	binary.BigEndian.PutUint32(out[8:], h2)
	binary.BigEndian.PutUint32(out[12:], h3)
	binary.BigEndian.PutUint32(out[16:], h4)

	return out
}
