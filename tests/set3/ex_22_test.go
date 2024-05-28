package set3

import (
	"main/pkg/utils"
	"testing"
)

var time uint32 = 0

func CurrentTime() (uint32, error) {
	diff, err := utils.GetSecureRandomUint32(40, 1000)
	if err != nil {
		return 0, err
	}

	time += diff
	return time, nil
}

func TestSolveEx22(t *testing.T) {
	seed, err := CurrentTime()
	if err != nil {
		t.Fatal(err)
	}

	secretMt := utils.MT19937Rng{}
	secretMt.Seed(seed)

	randomVal := secretMt.GetRandomUint32()

	testSeed, err := CurrentTime()
	if err != nil {
		t.Fatal(err)
	}

	for {
		mt := utils.MT19937Rng{}
		mt.Seed(testSeed)
		if randomVal == mt.GetRandomUint32() {
			break
		}
		testSeed--
	}

	if testSeed != seed {
		t.Fatalf("Cracked seed does not match used %d != %d", testSeed, seed)
	}
}
