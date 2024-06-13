package set5

import (
	"bytes"
	"main/pkg/utils"
	"testing"
)

func TestSolveEx39(t *testing.T) {
	pub, priv, err := utils.GenRSAPair(4096)
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte("hello world!")

	cipher, err := utils.RSAEncrypt(pub, expected)
	if err != nil {
		t.Fatal(err)
	}

	plain := utils.RSADecrypt(priv, cipher)

	if !bytes.Equal(plain, expected) {
		t.Fatalf("plain text and decrypted plain text mismatch: '%v' != '%v'", expected, plain)
	}
}
