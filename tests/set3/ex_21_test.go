package set3

import (
	"main/pkg/utils"
	"testing"
)

func TestSolveEx21(t *testing.T) {
	expected := uint32(4123659995)

	mt := utils.MT19937Rng{}
	mt.Seed(uint32(5489))

	for i := 0; i < 9999; i++ {
		_ = mt.GetRandomUint32()
	}

	rand := mt.GetRandomUint32()
	if rand != expected {
		t.Fatalf("10000th random number mismatch: %d != %d", rand, expected)
	}
}
