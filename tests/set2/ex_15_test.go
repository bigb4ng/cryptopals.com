package set2

import (
	_ "embed"
	"main/pkg/utils"
	"testing"
)

func TestSolveEx15(t *testing.T) {
	test1 := []byte("ICE ICE BABY\x04\x04\x04\x04")
	_, err := utils.UnpadPkcs7(test1, len(test1))
	if err != nil {
		t.Fatalf("correct padding returned error: %v", err)
	}

	test2 := []byte("ICE ICE BABY\x05\x05\x05\x05")
	_, err = utils.UnpadPkcs7(test2, len(test2))
	if err == nil {
		t.Fatal("incorrect padding did not return an error")
	}

	test3 := []byte("ICE ICE BABY\x01\x02\x03\x04")
	_, err = utils.UnpadPkcs7(test3, len(test3))
	if err == nil {
		t.Fatal("incorrect padding did not return an error")
	}
}
