package utils

import (
	"crypto"
	"math/big"
)

type DSAParams struct {
	P, Q, G *big.Int
}

type DSAPubKey struct {
	Params *DSAParams
	Y      *big.Int
}

type DSAPrivKey struct {
	Params *DSAParams
	X      *big.Int
}

func HashSumBigInt(data []byte, hash crypto.Hash) *big.Int {
	hashBuf := make([]byte, 0, hash.Size())
	digest := hash.New()
	digest.Write(data)
	hashBuf = digest.Sum(hashBuf)
	return new(big.Int).SetBytes(hashBuf)
}

func GenDSAPair(params *DSAParams) (*DSAPubKey, *DSAPrivKey, error) {
	// x = random from {1..q-1}
	x, err := GetSecureRandomBigInt(BigOne, params.Q)
	if err != nil {
		return nil, nil, err
	}

	// y = g**x mod p
	y := new(big.Int).Exp(params.G, x, params.P)

	return &DSAPubKey{params, y}, &DSAPrivKey{params, x}, nil
}

var LastK *big.Int

func DSASign(data []byte, priv *DSAPrivKey) (r, s *big.Int, err error) {
	for {
		// k = random from {1..q-1}
		LastK, err = GetSecureRandomBigInt(BigOne, priv.Params.Q)
		if err != nil {
			return
		}
		kInv := InverseModulo(LastK, priv.Params.Q)

		// r = (g**k mod p) mod q
		r = new(big.Int).Exp(priv.Params.G, LastK, priv.Params.P)
		r.Mod(r, priv.Params.Q)

		if r.Sign() == 0 {
			continue
		}

		// s = invmod(k, q) * (H(m) + xr) mod q
		s = new(big.Int).Mul(priv.X, r)
		s.Add(s, new(big.Int).SetBytes(data))
		s.Mod(s, priv.Params.Q)
		s.Mul(s, kInv)
		s.Mod(s, priv.Params.Q)

		if s.Sign() == 0 {
			continue
		}

		return
	}
}

func DSAVerify(data []byte, pubKey *DSAPubKey, r, s *big.Int) bool {
	// verify 0 < r < q
	if r.Sign() <= 0 || r.Cmp(pubKey.Params.Q) >= 0 {
		return false
	}

	// verify 0 < s < q
	if s.Sign() <= 0 || s.Cmp(pubKey.Params.Q) >= 0 {
		return false
	}

	w := InverseModulo(s, pubKey.Params.Q)

	u1 := new(big.Int).SetBytes(data)
	u1.Mul(u1, w)
	u1.Mod(u1, pubKey.Params.Q)
	u1.Exp(pubKey.Params.G, u1, pubKey.Params.P)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, pubKey.Params.Q)
	u2.Exp(pubKey.Y, u2, pubKey.Params.P)

	v := new(big.Int).Mul(u1, u2)
	v.Mod(v, pubKey.Params.P)
	v.Mod(v, pubKey.Params.Q)

	return v.Cmp(r) == 0
}
