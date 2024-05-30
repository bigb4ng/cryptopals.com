package utils

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
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
	bytesQueue []byte
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

func BreakLeftShiftAndMask(x, shift, mask uint32) uint32 {
	ans := uint32(0)
	mid := uint32(0)

	for curShift := uint32(0); curShift < 32-shift; curShift += shift {
		ans |= MaskBits(x, curShift, curShift+shift) ^ mid
		mid = (MaskBits(ans, curShift, curShift+shift) << shift) & mask
	}

	ans |= MaskBits(x, 32-32%shift, 32) ^ mid
	return ans
}

func BreakRightShift(x, shift uint32) uint32 {
	ans := uint32(0)
	mid := uint32(0)

	for curShift := uint32(32); curShift >= shift; curShift -= shift {
		ans |= MaskBits(x, curShift-shift, curShift) ^ mid
		mid = MaskBits(ans, curShift-shift, curShift) >> shift
	}

	ans |= MaskBits(x, 0, 32%shift) ^ mid
	return ans
}

func Untemper(x uint32) uint32 {
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

func (mt *MT19937Rng) populateBytes() {
	rand := mt.GetRandomUint32()
	mt.bytesQueue = make([]byte, 4)
	binary.LittleEndian.PutUint32(mt.bytesQueue, rand)
}

func (mt *MT19937Rng) Read(p []byte) (n int, e error) {
	for i := 0; i < len(p); i++ {
		if len(mt.bytesQueue) == 0 {
			mt.populateBytes()
		}

		p[i] = mt.bytesQueue[0]
		mt.bytesQueue = mt.bytesQueue[1:]
	}

	return len(p), nil
}

func (mt *MT19937Rng) Encrypt(src []byte, key uint16) []byte {
	mt.Seed(uint32(key))

	keyStream := make([]byte, len(src))
	_, _ = io.ReadFull(mt, keyStream)

	return Xor(src, keyStream)
}

func BruteforceMT19937State(src, srcIndex, start, end uint32) (uint32, bool) {
	stateVal := Untemper(src)

	mt := MT19937Rng{}
	found := false
	i := start
	for ; i <= end; i++ {
		mt.Seed(i)
		mt.twist()

		if stateVal == mt.StateArray[srcIndex] {
			found = true
			break
		}
	}

	return i, found
}
