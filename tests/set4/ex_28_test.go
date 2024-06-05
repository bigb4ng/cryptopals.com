package set4

import (
	"bytes"
	_ "embed"
	"main/pkg/utils"
	"testing"
)

func TestSolveEx28(t *testing.T) {
	secret := []byte("Top Secret")
	msg := []byte("You shall not forge!")

	signedMsg := utils.SignMessageSHA1(msg, secret)
	if !utils.VerifyMessageSHA1(signedMsg, secret) {
		t.Fatal("failed verifying signed message")
	}

	signedMsg = bytes.Replace(signedMsg, []byte("not"), []byte("yes"), 1)
	if utils.VerifyMessageSHA1(signedMsg, secret) {
		t.Fatalf("successfully modified signed message: %s", signedMsg)
	}

	anotherMsg := []byte("You shall not forge!")
	anotherSignedMsg := utils.SignMessageSHA1(anotherMsg, []byte("letmein"))
	if utils.VerifyMessageSHA1(anotherSignedMsg, secret) {
		t.Fatalf("successfully forged signed message: %s", anotherSignedMsg)
	}
}
