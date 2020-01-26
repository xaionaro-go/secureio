package secureio

import (
	"crypto/aes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt(t *testing.T) {
	rand.Seed(0)

	key := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)

	assert.NoError(t, err)
	plainBytes := make([]byte, 65534)
	_, err = rand.Read(plainBytes)

	cipherInstance, err := aes.NewCipher(key)
	assert.NoError(t, err)

	encryptedBytes := make([]byte, 65536)
	encrypt(cipherInstance, iv, encryptedBytes, plainBytes)

	assert.NotEqual(t, plainBytes, encryptedBytes[:len(plainBytes)])

	decryptedBytes := make([]byte, 65536)
	decrypt(cipherInstance, iv, decryptedBytes, encryptedBytes)

	assert.Equal(t, plainBytes, decryptedBytes[:len(plainBytes)])
}
