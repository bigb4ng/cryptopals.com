package set5

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"main/pkg/utils"
	"math"
	"math/big"
	"testing"
	"unsafe"
)

type UserData struct {
	salt uint32
	v    *big.Int
	B    *big.Int
	b    *big.Int
	u    *big.Int
	K    [sha256.Size]byte
}

var (
	N = &utils.DiffieHellmanP
	g = &utils.DiffieHellmanG
	k = new(big.Int).SetInt64(3)
)

type serverEx36 struct {
	database map[string]UserData
}

func saltBytes(salt uint32, bytes []byte) []byte {
	saltedBytes := make([]byte, int(unsafe.Sizeof(salt))+len(bytes))
	binary.BigEndian.PutUint32(saltedBytes, salt)
	copy(saltedBytes[unsafe.Sizeof(salt):], bytes)
	return saltedBytes
}

func NewServerEx36() (*serverEx36, error) {

	return &serverEx36{
		database: make(map[string]UserData),
	}, nil
}

func (s *serverEx36) RegisterUser(I string, salt uint32, v *big.Int) error {
	_, ok := s.database[I]
	if ok {
		return fmt.Errorf("user does not exist")
	}

	s.database[I] = UserData{
		salt: salt,
		v:    v,
	}

	return nil
}

func (s *serverEx36) StartSession(I string, A *big.Int) (uint32, *big.Int, error) {
	_, ok := s.database[I]
	if !ok {
		return 0, nil, fmt.Errorf("user does not exist")
	}

	user := s.database[I]

	b, err := utils.GetSecureRandomUint32(2, math.MaxUint32)
	if err != nil {
		return 0, nil, err
	}
	user.b = new(big.Int).SetUint64(uint64(b))

	B := B(user.v, user.b)

	user.u = u(A, B)

	user.K = serverK(A, user.b, user.v, user.u)

	s.database[I] = user

	return user.salt, B, nil
}

func (s *serverEx36) Login(email string, hmacBytes []byte) bool {
	user, ok := s.database[email]
	if !ok {
		return false
	}

	return hmac.Equal(M1(user.K, user.salt), hmacBytes)
}

// xH = SHA256(salt|password), x = integer of xH
func x(salt uint32, password []byte) *big.Int {
	xH := sha256.Sum256(saltBytes(salt, password))
	return new(big.Int).SetBytes(xH[:])
}

// B = k*v + g**b % N
func B(v, b *big.Int) *big.Int {
	return new(big.Int).Add(new(big.Int).Mul(k, v), new(big.Int).Exp(g, b, N))
}

// v = g**x % N
func v(g, x *big.Int) *big.Int {
	return new(big.Int).Exp(g, x, N)
}

// uH = SHA256(A|B), u = integer of uH
func u(A, B *big.Int) *big.Int {
	pubKeyConcat := append(A.Bytes(), B.Bytes()...)
	uH := sha256.Sum256(pubKeyConcat)
	return new(big.Int).SetBytes(uH[:])
}

// S = (B - k * g**x)**(a + u * x) % N
func clientK(a, B, u, x *big.Int) [sha256.Size]byte {
	Sbase := new(big.Int).Sub(B, new(big.Int).Mul(k, new(big.Int).Exp(g, x, N)))
	Sexp := new(big.Int).Add(a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(Sbase, Sexp, N)
	return sha256.Sum256(S.Bytes())
}

// S = (A * v**u) ** b % N
func serverK(A, b, v, u *big.Int) [sha256.Size]byte {
	S := new(big.Int).Exp(new(big.Int).Mul(A, new(big.Int).Exp(v, u, N)), b, N)
	return sha256.Sum256(S.Bytes())
}

func M1(K [sha256.Size]byte, salt uint32) []byte {
	saltBuf := make([]byte, unsafe.Sizeof(salt))
	binary.BigEndian.PutUint32(saltBuf, salt)

	M1Digest := hmac.New(sha256.New, K[:])
	_, _ = M1Digest.Write(saltBuf)

	M1 := make([]byte, 0)
	M1 = M1Digest.Sum(M1)
	return M1[:]
}

func TestSolveEx36(t *testing.T) {
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

	A, a, err := utils.NewDHPair(N, g)
	if err != nil {
		t.Fatal(err)
	}

	salt, B, err := server.StartSession(username, A)
	if err != nil {
		t.Fatal(err)
	}

	u := u(A, B)
	K := clientK(a, B, u, x)
	M1 := M1(K, salt)

	if !server.Login(username, M1[:]) {
		t.Fatalf("failed logging in with username: %s and M1: %v", username, M1)
	}
}
