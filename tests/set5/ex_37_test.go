package set5

import (
	"crypto/sha256"
	"main/pkg/utils"
	"math"
	"math/big"
	"testing"
)

func TestSolveEx37(t *testing.T) {
	server, err := NewServerEx36()
	if err != nil {
		t.Fatal(err)
	}

	username := "admin@example.com"
	password := []byte("letmein!")

	salt, err := utils.GetSecureRandomUint32(0, math.MaxUint32)
	if err != nil {
		t.Fatal(err)
	}

	x := x(salt, password)
	v := v(g, x)

	err = server.RegisterUser(username, salt, v)
	if err != nil {
		t.Fatal(err)
	}

	A := new(big.Int).SetUint64(0)

	salt, _, err = server.StartSession(username, A)
	if err != nil {
		t.Fatal(err)
	}

	K := sha256.Sum256(new(big.Int).Bytes())
	M1 := M1(K, salt)

	if !server.Login(username, M1[:]) {
		t.Fatalf("failed logging in with username: %s and M1: %v", username, M1)
	}
}
