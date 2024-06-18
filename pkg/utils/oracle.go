package utils

import (
	"crypto/aes"
	"errors"
	"math/big"
)

type ECBOracleFunc func([]byte) ([]byte, error)
type CBCOracleFunc func([]byte, []byte) bool
type BleichenbacherOracleFunc func([]byte) bool

func BreakECBSuffixOracle(oracleFunc ECBOracleFunc) ([]byte, error) {
	plaintext := []byte{}
	shortestCipherLen, err := oracleFunc(plaintext)
	if err != nil {
		return nil, err
	}

	blockSize := 0
	for {
		plaintext = append(plaintext, 'A')
		tempCipher, err := oracleFunc(plaintext)
		if err != nil {
			return nil, err
		}
		if len(shortestCipherLen) < len(tempCipher) {
			blockSize = len(tempCipher) - len(shortestCipherLen)
			break
		}
	}

	if blockSize != aes.BlockSize {
		return nil, errors.New("detected block size is not consistent with AES")
	}

	plaintext = make([]byte, aes.BlockSize*3)
	for i := range plaintext {
		plaintext[i] = 'A'
	}
	ciphertext, err := oracleFunc(plaintext)
	if err != nil {
		return nil, err
	}

	if !DetectAESInECB(ciphertext, 2) {
		return nil, errors.New("given oracle is not consistent with ECB mode")
	}

	// ....|....|....|
	// AAA*|AAA|SECRET
	// AAS*|AA|SECRET
	// brute first block
	var decryptedSuffix []byte
	plaintext = make([]byte, blockSize*2)
	foundMatch := false
	for i := 0; foundMatch || i == 0; i++ {
		foundMatch = false
		copy(plaintext, plaintext[1:])
		for j := 0; j <= 255; j++ {
			plaintext[blockSize-1] = byte(j)

			ciphertext, err := oracleFunc(plaintext[:blockSize*2-1-i%blockSize])
			if err != nil {
				return nil, err
			}

			if DetectAESInECB(ciphertext, 2) {
				decryptedSuffix = append(decryptedSuffix, byte(j))
				foundMatch = true
				break
			}
		}
	}

	return decryptedSuffix, nil
}

func BreakCBCBlockPaddingOracle(ciphertext []byte, iv []byte, checkPadding CBCOracleFunc) []byte {
	result := make([]byte, 16)

	origIv := make([]byte, len(iv))
	copy(origIv, iv)

	for i := range iv {
		for j := 0; j < 256; j++ {
			iv[aes.BlockSize-1-i] = byte(j)

			if checkPadding(ciphertext, iv) {
				break
			}
		}

		result[aes.BlockSize-1-i] = iv[aes.BlockSize-1-i] ^ origIv[aes.BlockSize-1-i] ^ byte(i+1)

		// setup padding for next
		for j := aes.BlockSize - 1 - i; j < aes.BlockSize; j++ {
			iv[j] = iv[j] ^ byte(i+1) ^ byte(i+2)
		}
	}

	return result
}

func BreakBleichenbacherPaddingOracle(cipher []byte, pub *RSAPubKey, verify BleichenbacherOracleFunc) []byte {
	bBuf := make([]byte, pub.N.BitLen()/8)
	bBuf[1] = 0x01
	B := new(big.Int).SetBytes(bBuf)

	twoB := new(big.Int).Mul(BigTwo, B)
	threeB := new(big.Int).Mul(BigThree, B)

	c0 := new(big.Int).SetBytes(cipher)

	// Step 1
	M := []BigInterval{{twoB, new(big.Int).Sub(threeB, BigOne)}}

	si := step2A(threeB, c0, pub, verify)

	for {
		if len(M) > 1 {
			// Step 2.b
			si = nextSi(si, c0, pub, verify)
		} else {
			si = step2C(twoB, threeB, si, c0, pub.E, pub.N, M, verify)
		}

		M = step3(si, B, pub.N, M)
		if len(M) == 1 && M[0].a.Cmp(M[0].b) == 0 {
			break
		}

		si.Mul(si, BigTwo)
	}

	mRecovered := step4(M[0].a, BigOne, pub.N)
	return mRecovered
}

func calcCPrime(c, s, e, n *big.Int) *big.Int {
	cPrime := new(big.Int).Set(s)
	cPrime.Exp(cPrime, e, n)
	cPrime.Mul(cPrime, c)
	cPrime.Mod(cPrime, n)
	return cPrime
}

func step2A(threeB, c0 *big.Int, pub *RSAPubKey, verify BleichenbacherOracleFunc) *big.Int {
	rem := new(big.Int)
	si := new(big.Int).Set(pub.N)
	si.QuoRem(si, threeB, rem)
	if rem.Sign() > 0 {
		si.Add(si, BigOne)
	}

	return nextSi(si, c0, pub, verify)
}

func nextSi(si, c0 *big.Int, pub *RSAPubKey, verify BleichenbacherOracleFunc) *big.Int {
	c1 := calcCPrime(c0, si, pub.E, pub.N)
	for !verify(c1.Bytes()) {
		si.Add(si, BigOne)
		c1 = calcCPrime(c0, si, pub.E, pub.N)
	}

	return si
}

func step2C(twoB, threeB, prevSi, c0, E, N *big.Int, M []BigInterval, verify BleichenbacherOracleFunc) *big.Int {
	rem := new(big.Int)

	// ri >= 2 * (b * prevS - 2 * B) / N
	ri := new(big.Int).Set(M[0].b)
	ri.Mul(ri, prevSi)
	ri.Sub(ri, twoB)
	ri.Mul(ri, BigTwo)
	ri.QuoRem(ri, N, rem)
	if rem.Sign() > 0 {
		ri.Add(ri, BigOne)
	}

	for {
		// si >= (2 * B + ri * n) / b
		si := new(big.Int).Mul(ri, N)
		si.Add(si, twoB)
		si.QuoRem(si, M[0].b, rem)
		// since si in Z add 1 to be "greater or equal"
		if rem.Sign() > 0 {
			si.Add(si, BigOne)
		}

		// si < (3 * B + ri * n) / a
		maxSi := new(big.Int).Mul(ri, N)
		maxSi.Add(maxSi, threeB)
		maxSi.QuoRem(maxSi, M[0].a, rem)
		// if we have remainder we can squeeze another si that is "less"
		if rem.Sign() > 0 {
			maxSi.Add(maxSi, BigOne)
		}

		for si.Cmp(maxSi) < 0 {
			ci := calcCPrime(c0, si, E, N)
			if verify(ci.Bytes()) {
				return si
			}
			si.Add(si, BigOne)
		}

		ri.Add(ri, BigOne)
	}
}

func step3(si, B, N *big.Int, M []BigInterval) []BigInterval {
	newM := make([]BigInterval, 0, len(M))

	one := new(big.Int).SetInt64(1)
	twoB := new(big.Int).SetInt64(2)
	twoB.Mul(twoB, B)
	threeB := new(big.Int).SetInt64(3)
	threeB.Mul(threeB, B)
	rem := new(big.Int)

	for i, interval := range M {
		// r >= ceil((a * si - 3*B + 1) / n)
		r := new(big.Int).Mul(interval.a, si)
		r.Sub(r, threeB)
		r.Add(r, one)
		r.QuoRem(r, N, rem)
		if rem.Sign() > 0 {
			r.Add(r, one)
		}

		// r <= floor((b * si - 2*B) / n)
		rMax := new(big.Int).Mul(interval.b, si)
		rMax.Sub(rMax, twoB)
		rMax.Quo(rMax, N)

		for r.Cmp(rMax) <= 0 {
			a := new(big.Int).Mul(r, N)
			a.Add(a, twoB)
			a.QuoRem(a, si, rem)
			if rem.Sign() > 0 {
				a.Add(a, one)
			}

			b := new(big.Int).Mul(r, N)
			b.Add(b, threeB)
			b.Sub(b, one)
			b.Quo(b, si)

			newRange := BigInterval{
				MaxBigInt(interval.a, a), MinBigInt(interval.b, b),
			}

			if newRange.a.Cmp(newRange.b) <= 0 {
				newM = append(newM, newRange)
			}

			r.Add(r, one)
			i++
		}
	}

	return newM
}

func step4(a, s0, N *big.Int) []byte {
	s0Inv := InverseModulo(s0, N)
	mRecovered := new(big.Int).Mul(a, s0Inv)
	mRecovered.Mod(mRecovered, N)

	return mRecovered.Bytes()
}
