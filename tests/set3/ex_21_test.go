package set3

import (
	"main/pkg/utils"
	"testing"
)

func TestSolveEx21(t *testing.T) {
	expected := []uint32{
		0, 4194449, 1288460453, 2455814784, 1331836786, 2345738925, 1292321498, 2551391786, 3168200698, 638584545, 146627809, 3938721533, 2071957228, 311258430, 1962603293, 135880935, 4148935099, 2360856212, 1861517898, 2135539869, 1313431726, 3729126809, 198155202, 3021995719, 3727062276, 233662513, 4104291191, 3418335140, 1941679773, 2082844158, 2327259828, 4029641428, 3374424533, 3273013610, 827078284, 3617734058, 3333789930, 215605719, 3914261531, 842923033, 4051474239, 1433747950, 2254826943, 2565800623, 1009379183, 3474488801, 2614438965, 3397018414, 2243004583, 2620900104, 1213104164, 4074324635, 871537539, 1764692889, 835075083, 3419736020, 1489459140, 544480791, 998159213, 4226353388, 3659825056, 3691330801, 3152666720, 1686467052, 1718261921, 2731990977, 3291853587, 3019527931, 375231826, 262985529, 3972193974, 2696304290, 1478618374, 3695341138, 3307230866, 523332111, 3976407827, 4273316057, 4077135178, 3368863660, 1606633126, 2050691514, 1941342717, 2313021049, 4270460697, 1854436795, 1925647079, 3303814407, 1351640594, 1441752319, 172493080, 1639499907, 2020801055, 3023885696, 4122727330, 52152365, 3973711853, 783009855, 561369468, 2327759484,
	}

	mt := utils.MT19937Rng{}
	mt.Seed(uint32(0))

	for i, expectedRand := range expected {
		rand := mt.GetRandomUint32()
		if rand != expectedRand {
			t.Fatalf("Random number mismatch at index %d: %d != %d", i, rand, expectedRand)
		}
	}
}
