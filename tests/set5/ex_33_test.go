package set5

import (
	"main/pkg/utils"
	"math/big"
	"testing"
)

func TestSolveEx33(t *testing.T) {
	A, a, err := utils.NewDHPair(&utils.DiffieHellmanP, &utils.DiffieHellmanG)
	if err != nil {
		t.Fatal(err)
	}

	B, b, err := utils.NewDHPair(&utils.DiffieHellmanP, &utils.DiffieHellmanG)
	if err != nil {
		t.Fatal(err)
	}

	var s1, s2 big.Int
	s1.Exp(A, b, &utils.DiffieHellmanP)
	s2.Exp(B, a, &utils.DiffieHellmanP)

	if s1.Cmp(&s2) != 0 {
		t.Fatalf("s1 and s2 are not equal: %s != %s", s1.String(), s2.String())
	}
}
