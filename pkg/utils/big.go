package utils

import (
	"math/big"
)

var (
	BigOne   = new(big.Int).SetInt64(1)
	BigTwo   = new(big.Int).SetInt64(2)
	BigThree = new(big.Int).SetInt64(3)
)

type BigInterval struct {
	a, b *big.Int
}

func MaxBigInt(a, b *big.Int) *big.Int {
	if a.Cmp(b) > 0 {
		return a
	}
	return b
}

func MinBigInt(a, b *big.Int) *big.Int {
	if a.Cmp(b) < 0 {
		return a
	}
	return b
}

// ExtendedGCD implements Extended Euclidean GCD algorithm. a and b must be positive.
func ExtendedGCD(x, y, a, b *big.Int) *big.Int {
	zero := new(big.Int).SetInt64(0)
	one := new(big.Int).SetInt64(1)

	oldR, r := new(big.Int).Set(a), new(big.Int).Set(b)
	oldS, s := new(big.Int).Set(one), new(big.Int).Set(zero)
	oldT, t := new(big.Int).Set(zero), new(big.Int).Set(one)

	for r.Sign() != 0 {
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

	if x.Sign() < 0 {
		x.Add(&x, b)
	}

	return &x
}

// CubeRoot calculates the cube root of a big.Int number using Halley's method.
func CubeRoot(n *big.Int) *big.Int {
	one := new(big.Float).SetInt64(1)
	two := new(big.Float).SetInt64(2)

	a := new(big.Float).SetInt(n)
	twoA := new(big.Float).SetInt(n)
	twoA.Mul(twoA, two)

	Xn := new(big.Float)
	XnPlus1 := new(big.Float).SetInt(n)

	for {
		Xn.Set(XnPlus1)

		cubeXn := new(big.Float).Set(Xn)
		cubeXn.Mul(cubeXn, Xn)
		cubeXn.Mul(cubeXn, Xn)

		nominator := new(big.Float).Set(cubeXn)
		nominator.Add(nominator, twoA)

		denominator := new(big.Float).Set(cubeXn)
		denominator.Mul(denominator, two)
		denominator.Add(denominator, a)

		coefficient := new(big.Float).Quo(nominator, denominator)
		XnPlus1 = new(big.Float).Mul(Xn, coefficient)

		if new(big.Float).Abs(new(big.Float).Sub(Xn, XnPlus1)).Cmp(one) < 0 {
			res, _ := XnPlus1.Int(nil)
			return res
		}
	}
}
