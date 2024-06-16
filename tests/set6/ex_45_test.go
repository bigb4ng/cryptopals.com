package set6

import (
	"main/pkg/utils"
	"math/big"
	"testing"
)

func TestSolveEx45Part1(t *testing.T) {
	data := []byte("Hello, world")
	paramsZeroG := &utils.DSAParams{
		P: params.P,
		// so that g ** u1 == 1, since
		// u1 = (m * w) mod q and 0 ** 0 = 1
		Q: new(big.Int).SetBytes(data),
		G: new(big.Int),
	}

	pub := &utils.DSAPubKey{
		Params: paramsZeroG,
		// so that y ** u2 = 1
		Y: utils.BigOne,
	}

	if !utils.DSAVerify(data, pub, utils.BigOne, utils.BigOne) {
		t.Fatal("failed forging signature")
	}
}

func TestSolveEx45Part2(t *testing.T) {
	data := []byte("Goodbye, world")

	paramsBadG := &utils.DSAParams{
		P: params.P,
		Q: params.Q,
		G: new(big.Int).Add(params.P, utils.BigOne),
	}

	pub, _, err := utils.GenDSAPair(paramsBadG)
	if err != nil {
		t.Fatal(err)
	}

	if !utils.DSAVerify(data, pub, utils.BigOne, utils.BigOne) {
		t.Fatal("failed forging signature")
	}

	randomSign, _ := utils.GetSecureRandomBigInt(utils.BigOne, paramsBadG.Q)
	if !utils.DSAVerify(data, pub, utils.BigOne, randomSign) {
		t.Fatal("failed forging signature")
	}
}
