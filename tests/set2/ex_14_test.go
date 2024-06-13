package set2

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	_ "embed"
	"fmt"
	"main/pkg/utils"
	"testing"
)

var expectedSuffixEx14 = []byte("I like trains!!!!!!")

type ex14Oracle struct {
	key []byte
}

func NewEx14Oracle() (*ex14Oracle, error) {
	var key = make([]byte, 16)
	var n, err = rand.Read(key)

	if err != nil || n != 16 {
		return nil, fmt.Errorf("failed obtaining random key: %v", err)
	}

	return &ex14Oracle{key}, nil
}

func (o *ex14Oracle) Encrypt(src []byte) ([]byte, error) {
	randomPrefixLen, err := utils.GetSecureRandomUint32(0, 100)
	if err != nil {
		panic(err)
	}

	randomPrefix := make([]byte, randomPrefixLen)
	rand.Read(randomPrefix)

	plaintext := make([]byte, len(randomPrefix)+len(src)+len(expectedSuffixEx14))
	copy(plaintext[:len(randomPrefix)], randomPrefix)
	copy(plaintext[len(randomPrefix):], src)
	copy(plaintext[len(randomPrefix)+len(src):], expectedSuffixEx14)

	return utils.EncryptECBSlice(plaintext, o.key)
}

// TODO: test seems to occasionally return partial results about 5% of a time (consistent with 1/16 chance)
func TestSolveEx14(t *testing.T) {
	oracle, err := NewEx14Oracle()
	if err != nil {
		t.Fatal(err)
	}

	// verify block will only match if it is aligned
	// zzzzzzzzzz   | 0000000000000000 | verify  block     |  0000000000000000 | ABCDABCDABCDABCD | SECRET
	// zzzzzzzzzz     0000000000000000   BBBBBBBBAAAAAAAA    BBBBBBBBAAAAAAAA   0000000000000000    SEECRET
	// zzzzzzzzzz     000000000000000B   BBBBBBBAAAAAAAAB    BBBBBBBAAAAAAAA0   000000000000000S    EECRET

	verifyBlock := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	plaintext := make([]byte, aes.BlockSize*4)
	copy(plaintext[aes.BlockSize:], verifyBlock)
	copy(plaintext[aes.BlockSize*2:], verifyBlock)

	var emptyBlockValue []byte
	for {
		ciphertext, err := oracle.Encrypt(plaintext)
		if err != nil {
			t.Fatal(err)
		}

		for i := 0; i < len(ciphertext); i += aes.BlockSize {
			tmpBlock := ciphertext[i : i+aes.BlockSize]

			if bytes.Count(ciphertext, tmpBlock) == 2 {
				nextBlock := ciphertext[i+aes.BlockSize : i+aes.BlockSize*2]
				if bytes.Count(ciphertext, nextBlock) == 2 && !bytes.Equal(tmpBlock, nextBlock) {
					emptyBlockValue = tmpBlock
					break
				}
			}
		}
		if emptyBlockValue != nil {
			break
		}
	}

	// w8 for aligned blocks
	// zzzzzzzzzz   | known empty block | brute  block      | AAAAAAAAAAAAAAA S | ECRET
	// zzzzzzzzzz     0000000000000000   AAAAAAAAAAAAAAA*     AAAAAAAAAAAAAAA S   EECRET
	// zzzzzzzzzz     0000000000000000   AAAAAAAAAAAAAAS*     AAAAAAAAAAAAAA SE   ECRET
	plaintext = make([]byte, aes.BlockSize*2)
	for i := range plaintext {
		plaintext[i] = 1
	}

	var decryptedSuffix []byte

	foundMatch := false
	for i := 0; foundMatch || i == 0; i++ {
		foundMatch = false
		copy(plaintext, plaintext[1:])
		for j := 0; j <= 255; j++ {
			plaintext[aes.BlockSize-1] = byte(j)
			var ciphertext []byte
			bruteBlockOffset := 0

			for {
				ciphertext, err = oracle.Encrypt(append(make([]byte, aes.BlockSize), plaintext[:aes.BlockSize*2-1-i%aes.BlockSize]...))
				if err != nil {
					t.Fatal(err)
				}

				if bytes.Contains(ciphertext, emptyBlockValue) {
					// block is aligned
					bruteBlockOffset = bytes.Index(ciphertext, emptyBlockValue) + aes.BlockSize
					break
				}
			}

			if bytes.Count(ciphertext, ciphertext[bruteBlockOffset:bruteBlockOffset+aes.BlockSize]) == 2 {
				decryptedSuffix = append(decryptedSuffix, byte(j))
				foundMatch = true
				break
			}
		}
	}

	if len(decryptedSuffix) == 0 {
		t.Fatal("decrypted suffix is empty")
	}

	decryptedSuffix = decryptedSuffix[:len(decryptedSuffix)-1]

	if !bytes.Equal(decryptedSuffix, expectedSuffixEx14) {
		t.Fatalf("decrypted suffix does not match %v != %v", decryptedSuffix, expectedSuffixEx14)
	}
}
