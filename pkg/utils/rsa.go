package utils

import (
	"crypto"
	"crypto/rand"
	"math/big"
)

type RSAPubKey struct {
	E, N *big.Int
}

type RSAPrivKey struct {
	D, N *big.Int
}

func GenRSAPair(bits int) (*RSAPubKey, *RSAPrivKey, error) {
	var p, q, d, n, e *big.Int
	var err error

	for d == nil {
		for {
			p, err = rand.Prime(rand.Reader, bits>>1)
			if err != nil {
				return nil, nil, err
			}
			if p.ProbablyPrime(0) {
				break
			}
		}

		for {
			q, err = rand.Prime(rand.Reader, bits>>1)
			if err != nil {
				return nil, nil, err
			}
			if q.ProbablyPrime(0) && p.Cmp(q) != 0 {
				break
			}
		}

		// n = p * q
		n = new(big.Int).Mul(p, q)

		// totient = (p-1)*(q-1)
		bigOne := big.NewInt(1)
		totient := new(big.Int).Mul(new(big.Int).Sub(p, bigOne), new(big.Int).Sub(q, bigOne))

		e = big.NewInt(3)

		// d = invmod(e, et)
		d = InverseModulo(e, totient)
	}

	return &RSAPubKey{e, n}, &RSAPrivKey{d, n}, nil
}

func RSAEncrypt(pub *RSAPubKey, plain []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(plain)
	c := new(big.Int).Exp(m, pub.E, pub.N)
	return c.Bytes(), nil
}

func RSADecrypt(priv *RSAPrivKey, cipher []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	m := new(big.Int).Exp(c, priv.D, priv.N)
	return m.Bytes()
}

func RSASignPKCS1(priv *RSAPrivKey, data []byte, hash crypto.Hash) ([]byte, error) {
	padded, err := PadSignPKCS1(data, priv.N.BitLen()/8, hash)
	if err != nil {
		return nil, err
	}

	return RSAEncrypt(&RSAPubKey{
		E: priv.D,
		N: priv.N,
	}, padded)
}
