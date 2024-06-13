package utils

import (
	"math/big"
)

// ExtendedGCD implements Extended Euclidean GCD algorithm. a and b must be positive.
func ExtendedGCD(x, y, a, b *big.Int) *big.Int {
	zero := new(big.Int).SetInt64(0)
	one := new(big.Int).SetInt64(1)

	oldR, r := new(big.Int).Set(a), new(big.Int).Set(b)
	oldS, s := new(big.Int).Set(one), new(big.Int).Set(zero)
	oldT, t := new(big.Int).Set(zero), new(big.Int).Set(one)

	for r.Cmp(zero) != 0 {
		q := new(big.Int).Div(oldR, r)
		oldR, r = r, new(big.Int).Sub(oldR, new(big.Int).Mul(q, r))
		if x != nil {
			oldS, s = s, new(big.Int).Sub(oldS, new(big.Int).Mul(q, s))
		}
		if y != nil {
			oldT, t = t, new(big.Int).Sub(oldT, new(big.Int).Mul(q, t))
		}
	}

	if x != nil {
		x.Set(oldS)
	}
	if y != nil {
		y.Set(oldT)
	}

	return oldR
}

func InverseModulo(a, b *big.Int) *big.Int {
	one := new(big.Int).SetInt64(1)

	var x big.Int
	gcd := ExtendedGCD(&x, nil, a, b)

	if gcd.Cmp(one) != 0 {
		// a and b are not coprime
		return nil
	}

	if x.Int64() < 0 {
		x.Add(&x, b)
	}

	return &x
}
