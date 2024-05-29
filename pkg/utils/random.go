package utils

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// GetSecureRandomUint32 generates cryptographically secure random uint32 within [min, max)
func GetSecureRandomUint32(min, max uint32) (result uint32, err error) {
	if max <= min {
		err := errors.New("max number is less or equal to min")
		return 0, err
	}

	numbersRange := max - min
	randomBytes := make([]byte, binary.Size(result))
	n, err := rand.Read(randomBytes)
	if n != binary.Size(result) || err != nil {
		return 0, err
	}

	result = binary.BigEndian.Uint32(randomBytes)
	result = result%uint32(numbersRange) + min

	return result, nil
}

const (
	n = 624
	m = 397
	r = 31
	a = 0x9908b0df
	u = 11
	s = 7
	t = 15
	l = 18
	b = 0x9d2c5680
	c = 0xefc60000
)

// MT19937Rng implements the Mersenne Twister 19937 random number generator.
type MT19937Rng struct {
	StateArray [n]uint32
	StateIndex int
}

// Seed initializes the generator with the given seed.
func (mt *MT19937Rng) Seed(seed uint32) {
	mt.StateArray[0] = seed

	for i := uint32(1); i < n; i++ {
		mt.StateArray[i] = uint32(1812433253)*(mt.StateArray[i-1]^(mt.StateArray[i-1]>>30)) + i
	}

	mt.StateIndex = n
}

// GetRandomUint32 returns a random uint32 value.
func (mt *MT19937Rng) GetRandomUint32() uint32 {
	if mt.StateIndex >= n {
		mt.twist()
	}

	y := mt.StateArray[mt.StateIndex]
	mt.StateIndex++

	// Tempering transformations
	y ^= (y >> u)
	y ^= (y << s) & b
	y ^= (y << t) & c
	y ^= (y >> l)

	return y
}

func maskBits(x, from, to int) int {
	shift := to - from - 1
	return x & (((1 << shift) | (1<<shift - 1)) << from)
}

func BreakLeftShiftAndMask(x, shift, mask int) int {
	ans := 0
	mid := 0

	for curShift := 0; curShift < 32-shift; curShift += shift {
		ans |= maskBits(x, curShift, curShift+shift) ^ mid
		mid = (maskBits(ans, curShift, curShift+shift) << shift) & mask
	}

	ans |= maskBits(x, 32-32%shift, 32) ^ mid

	return ans
}

func BreakRightShift(x, shift int) int {
	ans := 0
	mid := 0

	for curShift := 32; curShift >= shift; curShift -= shift {
		ans |= maskBits(x, curShift-shift, curShift) ^ mid
		mid = maskBits(ans, curShift-shift, curShift) >> shift
	}

	ans |= maskBits(x, 0, 32%shift) ^ mid
	return ans
}

func Untemper(x int) int {
	x = BreakRightShift(x, l)
	x = BreakLeftShiftAndMask(x, t, c)
	x = BreakLeftShiftAndMask(x, s, b)
	x = BreakRightShift(x, u)
	return x
}

// twist generates the next n values of the state array.
func (mt *MT19937Rng) twist() {
	for i := 0; i < n; i++ {
		x := (mt.StateArray[i] & 0x80000000) + (mt.StateArray[(i+1)%n] & 0x7fffffff)
		xA := x >> 1
		if (x & 1) != 0 {
			xA ^= a
		}
		mt.StateArray[i] = mt.StateArray[(i+m)%n] ^ xA
	}
	mt.StateIndex = 0
}
