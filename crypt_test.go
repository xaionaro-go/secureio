package secureio

import (
	"math/rand"
	"testing"

	"github.com/aead/chacha20/chacha"
	"github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt(t *testing.T) {
	rand.Seed(0)

	key := make([]byte, chacha.KeySize)
	_, err := rand.Read(key)

	iv := make([]byte, ivSize)
	_, err = rand.Read(iv)

	assert.NoError(t, err)
	plainBytes := make([]byte, 65534)
	_, err = rand.Read(plainBytes)

	encryptedBytes := make([]byte, 65536)
	encrypt(key, iv, encryptedBytes, plainBytes)

	assert.NotEqual(t, plainBytes, encryptedBytes[:len(plainBytes)])

	decryptedBytes := make([]byte, 65536)
	decrypt(key, iv, decryptedBytes, encryptedBytes)

	assert.Equal(t, plainBytes, decryptedBytes[:len(plainBytes)])
}
