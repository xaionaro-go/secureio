package secureio

import (
	"bytes"
	"crypto/ed25519"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

var nonExistantDir = path.Join(`/dev`, `null`, `non_existant`)

func TestSaveKeyToFile_negative(t *testing.T) {
	// invalid file path
	assert.Error(t, saveKeyToPemFile(``, nil, nonExistantDir, nil))

	// invalid key
	assert.Error(t, saveKeyToPemFile(``, nil, `/dev/zero`, map[string]string{":": ":"}))
}

func testIdentity(t *testing.T) *Identity {
	_, key, err := ed25519.GenerateKey(bytes.NewReader(make([]byte, 65536)))
	assert.NoError(t, err)
	identity, err := NewIdentityFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestIdentity_generateAndSaveKeys_negative(t *testing.T) {
	identity := testIdentity(t)

	// invalid dir
	assert.Error(t, identity.generateAndSaveKeys(nonExistantDir))

	// invalid reader
	identity.cryptoRandReader = &bytes.Buffer{}
	dir, err := ioutil.TempDir(os.TempDir(), `secureio-unittest`)
	if !assert.NoError(t, err) {
		return
	}
	defer os.RemoveAll(dir)
	assert.Error(t, identity.generateAndSaveKeys(dir))
}

func TestLoadPublicKeyFromFile_negative(t *testing.T) {
	dir, err := ioutil.TempDir(os.TempDir(), `secureio-unittest`)
	if !assert.NoError(t, err) {
		return
	}
	defer os.RemoveAll(dir)

	// invalid key-file
	path := path.Join(dir, `id_ed25519.pub`)
	assert.NoError(t, saveKeyToPemFile(``, nil, path, nil))
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	assert.Error(t, loadPublicKeyFromFile(&key, path))
}

func TestLoadPrivateKeyFromFile_negative(t *testing.T) {
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)

	// invalid path
	assert.Error(t, loadPublicKeyFromFile(&key, nonExistantDir))

	// invalid key-file
	dir, err := ioutil.TempDir(os.TempDir(), `secureio-unittest`)
	if !assert.NoError(t, err) {
		return
	}
	defer os.RemoveAll(dir)
	path := path.Join(dir, `id_ed25519`)
	assert.NoError(t, saveKeyToPemFile(``, nil, path, nil))
	assert.Error(t, loadPublicKeyFromFile(&key, path))
}

func TestIdentity_loadKeys_negative(t *testing.T) {
	// invalid path
	assert.Error(t, (&Identity{}).loadKeys(nonExistantDir))
}

func TestIdentity_prepareKeys_negative(t *testing.T) {
	// invalid path
	assert.Error(t, (&Identity{}).prepareKeys(nonExistantDir))
}

func TestIdentity_VerifySignature_negative(t *testing.T) {
	identity := testIdentity(t)

	// signature does not match
	assert.Error(t, identity.VerifySignature(nil, nil))
}
