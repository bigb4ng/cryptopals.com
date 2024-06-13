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

	encryptedCookie, err := utils.EncryptECBSlice(cookie[:len(cookie)-1], pm.key)
	if err != nil {
		panic(err)
	}

	return encryptedCookie
}

func (pm *exProfileManager) decodeCookie(encryptedCookie []byte) map[string]string {
	paddedCookie, err := utils.DecryptECBSlice(encryptedCookie, pm.key)
	if err != nil {
		panic(err)
	}

	cookie, err := utils.UnpadPKCS7(paddedCookie, aes.BlockSize)
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
	email = utils.RemoveChars(email, '=', '&')

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

	blockStartOffset := aes.BlockSize - len("email=")
	fakeBlock := utils.PadPKCS7([]byte("admin"), aes.BlockSize)

	fakeEmailPayload := make([]byte, aes.BlockSize*2+blockStartOffset)
	copy(fakeEmailPayload, plaintext[:blockStartOffset])
	copy(fakeEmailPayload[blockStartOffset:], fakeBlock)
	copy(fakeEmailPayload[blockStartOffset+aes.BlockSize:], fakeBlock)

	// email= (A*offset) | fakeBlock | fakeBlock | &uid=1&role=user
	utils.PrintBlocks(append(make([]byte, blockStartOffset), fakeEmailPayload...), aes.BlockSize)
	fakeEmailCipher := pm.ProfileFor(fakeEmailPayload)
	utils.PrintBlocks(fakeEmailCipher, aes.BlockSize)

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
