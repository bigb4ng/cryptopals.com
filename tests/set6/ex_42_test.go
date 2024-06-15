package set6

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"main/pkg/utils"
	"math/big"
	"testing"
)

func TestRSASign(t *testing.T) {
	pub, priv, err := utils.GenRSAPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world")
	signed, _ := utils.RSASignPKCS1(priv, data, crypto.SHA256)

	verified, err := utils.RSAVerifySignPKCS1(pub, signed)
	if err != nil {
		t.Fatal(err)
	}

	if !verified {
		t.Fatalf("failed verifying correctly signed message")
	}

	signed[0] ^= 0x42
	verifiedModified, err := utils.RSAVerifySignPKCS1(pub, signed)
	if err != nil {
		t.Fatal(err)
	}

	if verifiedModified {
		t.Fatalf("wrongly verified modified signed message")
	}
}

func TestSolveEx42(t *testing.T) {
	pub, _, err := utils.GenRSAPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	one := new(big.Int).SetInt64(1)

	plain := []byte("hi mom")
	hash := sha256.Sum256(plain)

	// DATA || 00h || BT || FFh
	targetPrefix := make([]byte, 0, len(plain)+3)
	targetPrefix = append(targetPrefix, plain...)
	targetPrefix = append(targetPrefix, []byte{0x00, 0x01, 0xFF}...)

	// 00h || D
	targetSuffix := make([]byte, 1+len(utils.DigestHeaders[crypto.SHA256])+len(hash))
	hashObjectIdentifierLen := copy(targetSuffix[1:], utils.DigestHeaders[crypto.SHA256])
	copy(targetSuffix[1+hashObjectIdentifierLen:], hash[:])

	// PREFIX || SUFFIX || 00h...00h
	target := make([]byte, pub.N.BitLen()/8)
	prefixSize := copy(target, targetPrefix)
	copy(target[prefixSize:], targetSuffix)

	targetNum := new(big.Int).SetBytes(target)
	source := utils.CubeRoot(targetNum)

	for source.Cmp(pub.N) < 0 {
		forgedPlainNum := new(big.Int).Exp(source, pub.E, pub.N)
		forgedPlain := forgedPlainNum.Bytes()

		if bytes.Equal(forgedPlain[:len(targetPrefix)+len(targetSuffix)], target[:len(targetPrefix)+len(targetSuffix)]) {
			break
		}

		source.Add(source, one)
	}

	if source.Cmp(pub.N) >= 0 {
		t.Fatalf("failed forging signature for message")
	}

	verifiedModified, err := utils.RSAVerifySignPKCS1(pub, source.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if !verifiedModified {
		t.Fatalf("failed forged message does not pass signature test")
	}
}
