package set3

import (
	"bytes"
	_ "embed"
	"main/pkg/utils"
	"testing"
)

func TestSolveEx18(t *testing.T) {
	expected := []byte("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")

	key := []byte("YELLOW SUBMARINE")
	ciphertext, err := utils.Base64Decode([]byte("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := utils.CTRSlice(ciphertext, key, 0)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, expected) {
		t.Fatalf("plaintext %v != expected %v", plaintext, expected)
	}
}
