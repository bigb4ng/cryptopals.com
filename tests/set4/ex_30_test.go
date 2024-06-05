package set4

import (
	"bytes"
	"encoding/binary"
	"main/pkg/utils"
	"testing"

	"golang.org/x/crypto/md4"
)

func TestSolveEx30(t *testing.T) {
	secret := []byte("YELLOW SUBMARINE")
	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	signedMsg := utils.SignMessageMD4(msg, secret)
	signature := signedMsg[len(signedMsg)-md4.Size:]

	values := make([]uint32, 4)
	values[0] = binary.LittleEndian.Uint32(signature[0:])
	values[1] = binary.LittleEndian.Uint32(signature[4:])
	values[2] = binary.LittleEndian.Uint32(signature[8:])
	values[3] = binary.LittleEndian.Uint32(signature[12:])

	var forgedMsg []byte
	found := false
	for i := 0; i < 32 && !found; i++ {
		forgedMsg = bytes.Clone(msg)
		guessedLen := len(msg) + i
		lastBlock := forgedMsg[len(msg)/md4.BlockSize*md4.BlockSize-i:]

		gluePad := utils.MD4PadMessage(lastBlock, guessedLen/md4.BlockSize*md4.BlockSize)
		forgedMsg = append(forgedMsg[:len(msg)/md4.BlockSize*md4.BlockSize-i], gluePad...)

		secondPad := utils.MD4PadMessage([]byte(";admin=true;"), (guessedLen/md4.BlockSize+1)*md4.BlockSize)
		forgedMsg = append(forgedMsg, []byte(";admin=true;")...)

		newSha := utils.MD4ComputeBlock(secondPad, values[0], values[1], values[2], values[3])
		forgedMsg = append(forgedMsg, '.')
		forgedMsg = append(forgedMsg, newSha[:]...)

		found = utils.VerifyMessageMD4(forgedMsg, secret)
	}

	if !found {
		t.Fatal("failed finding verified cookie")
	}

	if forgedMsg == nil || !utils.VerifyMessageMD4(forgedMsg, secret) || !bytes.Contains(forgedMsg, []byte(";admin=true;")) {
		t.Fatalf("found cookie is invalid. found: %s", forgedMsg)
	}
}
