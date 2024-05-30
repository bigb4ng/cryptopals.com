package set3

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"main/pkg/utils"
	"math"
	"testing"
	"time"
)

func GeneratePasswordResetToken() ([]byte, uint32) {
	token := make([]byte, 20)
	mt := utils.MT19937Rng{}
	seed := uint32(time.Now().UnixNano())

	mt.Seed(seed)
	io.ReadFull(&mt, token)

	return utils.Base64Encode(token), seed
}

func TestSolveEx24Part2(t *testing.T) {
	token, expected := GeneratePasswordResetToken()
	tokenBytes, _ := utils.Base64Decode(token)
	lastNumBytes := utils.LastFullBlock(tokenBytes, 4)
	lastNum := binary.LittleEndian.Uint32(lastNumBytes)
	stateIndex := uint32(len(tokenBytes)/4 - 1)

	curTime := uint32(time.Now().UnixNano())
	guessedSeed, found := utils.BruteforceMT19937State(lastNum, stateIndex, curTime-200_000, curTime)

	if !found {
		t.Fatalf("Could not find matching state for range %d to %d at index %d", curTime-200_000, curTime, stateIndex)
	}

	if guessedSeed != expected {
		t.Fatalf("Guessed seed mismatch: %d != %d", guessedSeed, expected)
	}
}

func TestSolveEx24Part1(t *testing.T) {
	src := "Hello World!"

	prefixBytesLength, err := utils.GetSecureRandomUint32(5, 11)
	if err != nil {
		t.Fatalf("failed reading random bytes for prefix: %v", err)
	}

	prefixBytes := make([]byte, prefixBytesLength)
	n, err := rand.Read(prefixBytes)
	if err != nil || n != int(prefixBytesLength) {
		t.Fatalf("failed reading random bytes for prefix: %v", err)
	}

	finalPlaintext := make([]byte, int(prefixBytesLength)+len(src))
	copy(finalPlaintext[:prefixBytesLength], prefixBytes)
	copy(finalPlaintext[prefixBytesLength:], src)

	secretMt := utils.MT19937Rng{}
	encryptionKey := uint16(0x1337)
	ciphertext := secretMt.Encrypt(finalPlaintext, encryptionKey)

	lastRand := utils.Xor(utils.LastFullBlock(ciphertext, 4), []byte(src)[len(src)-len(ciphertext)%4-4:])
	lastRandNum := binary.LittleEndian.Uint32(lastRand)
	stateIndex := uint32(len(ciphertext)/4 - 1)
	guessedSeed, found := utils.BruteforceMT19937State(lastRandNum, stateIndex, 0, math.MaxUint16)

	if !found {
		t.Fatalf("Could not find matching state for range %d to %d at index %d", 0, math.MaxUint16, stateIndex)
	}

	if guessedSeed != uint32(encryptionKey) {
		t.Fatalf("Guessed encryption key mismatch: %d != %d", guessedSeed, encryptionKey)
	}
}
