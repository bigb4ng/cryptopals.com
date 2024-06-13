package utils

import (
	"crypto/sha1"
	"encoding/binary"
	"math/bits"

	"golang.org/x/crypto/md4"
)

const (
	_K0 = 0x5A827999
	_K1 = 0x6ED9EBA1
	_K2 = 0x8F1BBCDC
	_K3 = 0xCA62C1D6
)

func SHA1PadMessage(messageBlock []byte, prevLen int) []byte {
	paddedBlock := make([]byte, sha1.BlockSize)

	copy(paddedBlock, messageBlock)
	paddedBlock[len(messageBlock)] = 0x80

	lenInBits := uint64(len(messageBlock)+prevLen) << 3
	binary.BigEndian.PutUint64(paddedBlock[len(paddedBlock)-8:], lenInBits)

	return paddedBlock
}

func SHA1ComputeBlock(p []byte, h0, h1, h2, h3, h4 uint32) [sha1.Size]byte {
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

func MD4PadMessage(messageBlock []byte, prevLen int) []byte {
	paddedBlock := make([]byte, sha1.BlockSize)

	copy(paddedBlock, messageBlock)
	paddedBlock[len(messageBlock)] = 0x80

	lenInBits := uint64(len(messageBlock)+prevLen) << 3
	binary.LittleEndian.PutUint64(paddedBlock[len(paddedBlock)-8:], lenInBits)

	return paddedBlock
}

var shift1 = []int{3, 7, 11, 19}
var shift2 = []int{3, 5, 9, 13}
var shift3 = []int{3, 9, 11, 15}

var xIndex2 = []uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
var xIndex3 = []uint{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}

func MD4ComputeBlock(p []byte, a, b, c, d uint32) [md4.Size]byte {
	var X [16]uint32
	for len(p) >= md4.BlockSize {
		aa, bb, cc, dd := a, b, c, d

		j := 0
		for i := 0; i < 16; i++ {
			X[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
			j += 4
		}

		// If this needs to be made faster in the future,
		// the usual trick is to unroll each of these
		// loops by a factor of 4; that lets you replace
		// the shift[] lookups with constants and,
		// with suitable variable renaming in each
		// unrolled body, delete the a, b, c, d = d, a, b, c
		// (or you can let the optimizer do the renaming).
		//
		// The index variables are uint so that % by a power
		// of two can be optimized easily by a compiler.

		// Round 1.
		for i := uint(0); i < 16; i++ {
			x := i
			s := shift1[i%4]
			f := ((c ^ d) & b) ^ d
			a += f + X[x]
			a = bits.RotateLeft32(a, s)
			a, b, c, d = d, a, b, c
		}

		// Round 2.
		for i := uint(0); i < 16; i++ {
			x := xIndex2[i]
			s := shift2[i%4]
			g := (b & c) | (b & d) | (c & d)
			a += g + X[x] + 0x5a827999
			a = bits.RotateLeft32(a, s)
			a, b, c, d = d, a, b, c
		}

		// Round 3.
		for i := uint(0); i < 16; i++ {
			x := xIndex3[i]
			s := shift3[i%4]
			h := b ^ c ^ d
			a += h + X[x] + 0x6ed9eba1
			a = bits.RotateLeft32(a, s)
			a, b, c, d = d, a, b, c
		}

		a += aa
		b += bb
		c += cc
		d += dd

		p = p[md4.BlockSize:]
	}

	var out [md4.Size]byte
	binary.LittleEndian.PutUint32(out[0:], a)
	binary.LittleEndian.PutUint32(out[4:], b)
	binary.LittleEndian.PutUint32(out[8:], c)
	binary.LittleEndian.PutUint32(out[12:], d)

	return out
}
