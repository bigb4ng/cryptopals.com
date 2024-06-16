package set6

import (
	"bytes"
	"crypto/sha1"
	_ "embed"
	"main/pkg/utils"
	"math/big"
	"testing"
)

//go:embed "assets/44.txt"
var messagesEx44 []byte

type messageEx44 struct {
	plain []byte
	s, r  *big.Int
	m     *big.Int
}

func parseMessagesEx44(data []byte) ([]messageEx44, error) {
	lines := bytes.Split(data, []byte{'\n'})
	msgs := make([]messageEx44, len(lines)/4)
	for i := 0; i < len(lines); i += 4 {
		s, _ := new(big.Int).SetString(string(lines[i+1][3:]), 10)
		r, _ := new(big.Int).SetString(string(lines[i+2][3:]), 10)

		hash := lines[i+3][3:]
		if len(hash)%2 != 0 {
			hash = append([]byte{'0'}, hash...)
		}

		decode, err := utils.HexDecode(hash)
		if err != nil {
			return nil, err
		}

		m := new(big.Int).SetBytes(decode)
		msgs[i/4] = messageEx44{
			lines[i][5:],
			s,
			r,
			m,
		}
	}

	return msgs, nil
}

func TestSolveEx44(t *testing.T) {
	expected, err := utils.HexDecode([]byte("ca8f6f7c66fa362d40760d135b763eb8527d3d52"))
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := parseMessagesEx44(messagesEx44)
	if err != nil {
		t.Fatal(err)
	}

	// find two messages with same k.
	// since r = g**k mod p mod q they will also have the same r
	var msg1, msg2 messageEx44
	rs := make(map[string]int)
	for i := 0; i < len(parsed); i++ {
		j, ok := rs[parsed[i].r.String()]
		if !ok {
			rs[parsed[i].r.String()] = i
		} else {
			msg1, msg2 = parsed[j], parsed[i]
		}
	}

	k := new(big.Int).Sub(msg1.m, msg2.m)

	kDiv := new(big.Int).Sub(msg1.s, msg2.s)
	kDivInv := utils.InverseModulo(kDiv, params.Q)
	k.Mul(k, kDivInv)
	k.Mod(k, params.Q)

	recoveredX := recoverX(msg1.r, msg1.s, k, msg1.m)
	xHex := bytes.ToLower(utils.HexEncode(recoveredX.Bytes()))
	xHash := sha1.Sum(xHex)
	if !bytes.Equal(xHash[:], expected) {
		t.Fatalf("recovered x hash mismatched expected hash '%s' != '%s'", xHash, expected)
	}
}
