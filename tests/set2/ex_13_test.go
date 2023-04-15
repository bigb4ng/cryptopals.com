package set2

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	_ "embed"
	"fmt"
	"main/pkg/utils"
	"testing"
)

type exProfileManager struct {
	key []byte
}

func NewExProfileManager() (*exProfileManager, error) {
	var key = make([]byte, 16)
	var n, err = rand.Read(key)

	if err != nil || n != 16 {
		return nil, fmt.Errorf("failed obtaining random key: %v", err)
	}

	return &exProfileManager{key}, nil
}

func (pm *exProfileManager) encodeCookie(obj map[string]string) []byte {
	order := []string{"email", "uid", "role"}
	var cookie []byte

	for _, key := range order {
		cookie = append(cookie, []byte(fmt.Sprintf("%s=%s&", key, obj[key]))...)
	}

	encryptedCookie, err := utils.EncryptEcbSlice(cookie[:len(cookie)-1], pm.key)
	if err != nil {
		panic(err)
	}

	return encryptedCookie
}

func (pm *exProfileManager) decodeCookie(encryptedCookie []byte) map[string]string {
	paddedCookie, err := utils.DecryptEcbSlice(encryptedCookie, pm.key)
	if err != nil {
		panic(err)
	}

	cookie, err := utils.UnpadPkcs7(paddedCookie, aes.BlockSize)
	if err != nil {
		panic(err)
	}

	obj := make(map[string]string)

	pairs := bytes.Split(cookie, []byte{'&'})
	for _, pair := range pairs {
		kv := bytes.Split(pair, []byte{'='})
		obj[string(kv[0])] = string(kv[1])
	}

	return obj
}

func (pm *exProfileManager) ProfileFor(email []byte) []byte {
	email = utils.RemoveChar(email, '=')
	email = utils.RemoveChar(email, '&')

	obj := map[string]string{
		"email": string(email),
		"uid":   "1",
		"role":  "user",
	}

	return pm.encodeCookie(obj)
}

func (pm *exProfileManager) IsAdminCookie(encryptedCookie []byte) bool {
	userObj := pm.decodeCookie(encryptedCookie)
	return userObj["role"] == "admin"
}

func TestSolveEx13(t *testing.T) {
	pm, err := NewExProfileManager()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, aes.BlockSize*3)
	for i := range plaintext {
		plaintext[i] = 'A'
	}

	blockStartOffset := 0
	emptyCipherLen := 0
	for i := range plaintext {
		if i == 0 {
			emptyCipherLen = len(pm.ProfileFor([]byte{}))
			continue
		}
		profileCookie := pm.ProfileFor(plaintext[:i])
		if len(profileCookie) > emptyCipherLen {
			blockStartOffset = i - 1
			break
		}
	}

	t.Logf("blockStartOffset: %d", blockStartOffset)
	fakeBlock, err := utils.PadPkcs7([]byte("admin"), aes.BlockSize)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(len(fakeBlock))
	fakeEmailPayload := make([]byte, aes.BlockSize*2+blockStartOffset)
	copy(fakeEmailPayload, plaintext[:blockStartOffset])
	copy(fakeEmailPayload[blockStartOffset:], fakeBlock)
	copy(fakeEmailPayload[blockStartOffset+aes.BlockSize:], fakeBlock)

	// email= (A*offset) | fakeBlock | fakeBlock | &uid=1&role=user
	fakeEmailCipher := pm.ProfileFor(fakeEmailPayload)
	var encryptedAdminBlock []byte

	for i := aes.BlockSize; i < len(fakeEmailCipher); i += aes.BlockSize {
		tmpBlock := fakeEmailCipher[i : i+aes.BlockSize]
		if bytes.Count(fakeEmailCipher, tmpBlock) > 1 {
			encryptedAdminBlock = tmpBlock
			break
		}
	}

	if encryptedAdminBlock == nil {
		t.Fatal("failed finding fake admin block")
	}

	// email= (A*offset) | (A*pad) &uid=1&role= | user
	// email=AAAAAAAAAA  |  AAAA   &uid=1&role= | user

	roleBlockPaddingLen := aes.BlockSize - len("&uid=1&role=")
	fakeEmailPayload = make([]byte, blockStartOffset+roleBlockPaddingLen)
	copy(fakeEmailPayload, plaintext)
	fakeCipher := pm.ProfileFor(fakeEmailPayload)

	// replace to admin
	// email= (A*offset) | (A*pad) &uid=1&role= | admin
	copy(fakeCipher[2*aes.BlockSize:], encryptedAdminBlock)

	// verify fakeCipher for admin
	if !pm.IsAdminCookie(fakeCipher) {
		t.Fatal("cookie admin verification failed")
	}
}
