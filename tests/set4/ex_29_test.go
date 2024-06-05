package set4

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"main/pkg/utils"
	"testing"
)

func TestSolveEx29(t *testing.T) {
	secret := []byte("YELLOW SUBMARINE")
	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	signedMsg := utils.SignMessageSHA1(msg, secret)
	signature := signedMsg[len(signedMsg)-sha1.Size:]

	values := make([]uint32, 5)
	values[0] = binary.BigEndian.Uint32(signature[0:])
	values[1] = binary.BigEndian.Uint32(signature[4:])
	values[2] = binary.BigEndian.Uint32(signature[8:])
	values[3] = binary.BigEndian.Uint32(signature[12:])
	values[4] = binary.BigEndian.Uint32(signature[16:])

	var forgedMsg []byte
	found := false
	for i := 0; i < 32 && !found; i++ {
		forgedMsg = bytes.Clone(msg)
		guessedLen := len(msg) + i
		lastBlock := forgedMsg[len(msg)/sha1.BlockSize*sha1.BlockSize-i:]

		gluePad := utils.Sha1PadMessage(lastBlock, guessedLen/sha1.BlockSize*sha1.BlockSize)
		forgedMsg = append(forgedMsg[:len(msg)/sha1.BlockSize*sha1.BlockSize-i], gluePad...)

		secondPad := utils.Sha1PadMessage([]byte(";admin=true;"), (guessedLen/sha1.BlockSize+1)*sha1.BlockSize)
		forgedMsg = append(forgedMsg, []byte(";admin=true;")...)

		newSha := utils.Sha1ComputeBlock(secondPad, values[0], values[1], values[2], values[3], values[4])
		forgedMsg = append(forgedMsg, '.')
		forgedMsg = append(forgedMsg, newSha[:]...)

		found = utils.VerifyMessageSHA1(forgedMsg, secret)
	}

	if !found {
		t.Fatal("failed finding verified cookie")
	}

	if forgedMsg == nil || !utils.VerifyMessageSHA1(forgedMsg, secret) || !bytes.Contains(forgedMsg, []byte(";admin=true;")) {
		t.Fatalf("found cookie is invalid. found: %s", forgedMsg)
	}
}
