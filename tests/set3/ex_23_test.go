package set3

import (
	"main/pkg/utils"
	"testing"
	"time"
)

func TestSolveEx23(t *testing.T) {
	secretMt := utils.MT19937Rng{}
	secretMt.Seed(uint32(time.Now().UnixNano()))

	mt := utils.MT19937Rng{}

	for i := 0; i < 624; i++ {
		mt.StateArray[i] = uint32(utils.Untemper(int(secretMt.GetRandomUint32())))
	}
	mt.StateIndex = 624

	for i, val := range mt.StateArray {
		if secretMt.StateArray[i] != val {
			t.Fatalf("State array mismatch at index %d: %d != %d", i, val, secretMt.StateArray[i])
		}
	}
}
