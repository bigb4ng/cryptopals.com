package set6

import (
	"bytes"
	"main/pkg/utils"
	"testing"
)

type ex47Oracle struct {
	Pub  *utils.RSAPubKey
	priv *utils.RSAPrivKey
}

func NewEx47Oracle() (*ex47Oracle, error) {
	pub, priv, err := utils.GenRSAPair(256)
	if err != nil {
		return nil, err
	}

	return &ex47Oracle{
		pub, priv,
	}, nil
}

func (oracle *ex47Oracle) VerifyPKCS1(cipher []byte) bool {
	plain := utils.RSADecrypt(oracle.priv, cipher)
	return len(plain) == oracle.Pub.N.BitLen()/8-1 && plain[0] == 0x02
}

func TestSolveEx47(t *testing.T) {
	data := []byte("kick it, CC")
	oracle, err := NewEx47Oracle()
	if err != nil {
		t.Fatal(err)
	}

	expected := utils.PadEncryptPKCS1(data, oracle.Pub.N.BitLen()/8)

	c, err := utils.RSAEncrypt(oracle.Pub, expected)
	if err != nil {
		t.Fatal(err)
	}

	mRecovered := utils.BreakBleichenbacherPaddingOracle(c, oracle.Pub, oracle.VerifyPKCS1)

	if !bytes.Equal(expected[1:], mRecovered) {
		t.Fatalf("recovered message mismatched expected: '%v' != '%v'", mRecovered, expected)
	}
}
