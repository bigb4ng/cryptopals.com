package utils

import (
	"math"
	"math/big"
)

var DiffieHellmanP big.Int
var DiffieHellmanG big.Int

func init() {
	DiffieHellmanP.SetString(`ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
							e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
							3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
							6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
							24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
							c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
							bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
							fffffffffffff`, 16)

	DiffieHellmanG.SetInt64(2)
}

func NewDHPair(p, g *big.Int) (*big.Int, *big.Int, error) {
	randA, err := GetSecureRandomUint32(2, math.MaxUint32)
	if err != nil {
		return nil, nil, err
	}

	a := big.NewInt(int64(randA))
	a.Mod(a, p)

	var A big.Int
	A.Exp(g, a, p)

	return &A, a, nil
}
