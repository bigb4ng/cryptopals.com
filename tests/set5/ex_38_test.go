package set5

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"main/pkg/utils"
	"math"
	"math/big"
	"testing"
)

type EveEx38 struct {
	server     *serverEx36
	salt       uint32
	A, B, u, b *big.Int
	hmacBytes  []byte
}

func NewEveEx38() (*EveEx38, error) {
	server, err := NewServerEx36()
	if err != nil {
		return nil, err
	}
	return &EveEx38{
		server: server,
	}, nil
}

func (eve *EveEx38) RegisterUser(I string, salt uint32, v *big.Int) error {
	return eve.server.RegisterUser(I, salt, v)
}

func (eve *EveEx38) StartSession(I string, A *big.Int) (uint32, *big.Int, *big.Int, error) {
	eve.A = A

	salt, _, err := eve.server.StartSession(I, A)
	if err != nil {
		return 0, nil, nil, err
	}
	eve.salt = salt

	b, err := utils.GetSecureRandomUint32(2, math.MaxUint32)
	if err != nil {
		return 0, nil, nil, err
	}
	eve.b = new(big.Int).SetUint64(uint64(b))

	eve.B = simplifiedB(eve.b)
	eve.u = u(A, eve.B)

	return eve.salt, eve.B, eve.u, err
}

func (eve *EveEx38) Login(email string, hmacBytes []byte) bool {
	eve.hmacBytes = hmacBytes
	return eve.server.Login(email, hmacBytes)
}

// B = g**b % N
func simplifiedB(b *big.Int) *big.Int {
	return new(big.Int).Exp(g, b, N)
}

// S = (B)**(a + u * x) % N
func simplifiedClientK(a, B, u, x *big.Int) [sha256.Size]byte {
	Sexp := new(big.Int).Add(a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(B, Sexp, N)
	return sha256.Sum256(S.Bytes())
}

func (eve *EveEx38) BruteforcePassword() *string {
	passwords := []string{"admin", "123456", "letmein!", "password1", "ABCdef123!"}
	for _, password := range passwords {
		x := x(eve.salt, []byte(password))
		v := v(g, x)
		K := serverK(eve.A, eve.b, v, eve.u)
		if hmac.Equal(M1(K, eve.salt), eve.hmacBytes) {
			return &password
		}
	}

	return nil
}

func TestSolveEx38(t *testing.T) {
	server, err := NewEveEx38()
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

	A, a, err := utils.NewDHPair(N, g)
	if err != nil {
		t.Fatal(err)
	}

	salt, B, u, err := server.StartSession(username, A)
	if err != nil {
		t.Fatal(err)
	}

	K := simplifiedClientK(a, B, u, x)
	M1 := M1(K, salt)

	server.Login(username, M1[:])
	guessedPassword := server.BruteforcePassword()

	if guessedPassword == nil {
		t.Fatal("password bruteforce failed")
	}

	if !bytes.Equal([]byte(*guessedPassword), password) {
		t.Fatalf("guessed password mismatch '%v' != '%s'", *guessedPassword, password)
	}
}
