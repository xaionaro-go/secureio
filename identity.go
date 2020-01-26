package secureio

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ed25519"
)

const (
	//authorizedKeysFileName = `authorized_keys`
	publicFileName  = `id_ed25519`
	privateFileName = `id_ed25519.pub`
)

type Keys struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

type Identity struct {
	Keys Keys
}

/*func init() {
	switch runtime.GOOS {
	case "linux":
		devRandom, err := os.Open(`/dev/random`)
		if err != nil {
			rand.Reader = devRandom
		}
	}
}*/

func NewIdentity(keysDir string) (*Identity, error) {
	i := &Identity{}
	return i, i.prepareKeys(keysDir)
}

func NewIdentityFromPrivateKey(privKey ed25519.PrivateKey) *Identity {
	i := &Identity{}
	i.Keys.Private = privKey
	i.Keys.Public = privKey.Public().(ed25519.PublicKey)
	return i
}

func NewRemoteIdentity(keyPath string) (*Identity, error) {
	i := &Identity{}
	return i, loadPublicKeyFromFile(&i.Keys.Public, keyPath)
}

func NewRemoteIdentityFromPublicKey(pubKey ed25519.PublicKey) *Identity {
	i := &Identity{}
	i.Keys.Public = pubKey
	return i
}

func (i *Identity) savePublicKey(keysDir string) error {
	return saveKeyToPemFile(
		"ED25519 PUBLIC KEY",
		i.Keys.Public,
		filepath.Join(keysDir, publicFileName),
	)
}

func (i *Identity) savePrivateKey(keysDir string) error {
	return saveKeyToPemFile(
		"ED25519 PRIVATE KEY",
		i.Keys.Private,
		filepath.Join(keysDir, privateFileName),
	)
}

func saveKeyToPemFile(keyType string, key []byte, filePath string) error {
	keyFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return wrapErrorf("unable to open file: %w", err)
	}

	keyBlock := pem.Block{
		Type:    keyType,
		Headers: nil,
		Bytes:   key,
	}

	err = pem.Encode(keyFile, &keyBlock)
	if err != nil {
		return wrapErrorf("pem.Encode() returned an error: %w", err)
	}

	return nil
}

func (i *Identity) generateAndSaveKeys(keysDir string) error {
	var err error
	i.Keys.Public, i.Keys.Private, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return wrapErrorf("cannot generate keys: %w", err)
	}
	err = i.savePrivateKey(keysDir)
	if err == nil {
		err = i.savePublicKey(keysDir)
	}
	return wrapErrorf("cannot save keys: %w", err)
}

func loadPublicKeyFromFile(keyPtr *ed25519.PublicKey, path string) error {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return wrapErrorf("unable to read key: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if len(block.Bytes) != ed25519.PublicKeySize {
		return newErrWrongKeyLength(ed25519.PublicKeySize, uint(len(block.Bytes)))
	}
	*keyPtr = block.Bytes
	return nil
}

func loadPrivateKeyFromFile(keyPtr *ed25519.PrivateKey, path string) error {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return wrapErrorf("unable to read file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return newErrWrongKeyLength(ed25519.PrivateKeySize, uint(len(block.Bytes)))
	}
	*keyPtr = block.Bytes
	return nil
}

func (i *Identity) loadKeys(keysDir string) error {
	err := loadPrivateKeyFromFile(&i.Keys.Private, filepath.Join(keysDir, privateFileName))
	if err != nil {
		return wrapErrorf("Cannot load the private key: %w", err)
	}
	i.Keys.Public = i.Keys.Private.Public().(ed25519.PublicKey)
	return nil
}

func (i *Identity) prepareKeys(keysDir string) error {
	err := os.MkdirAll(keysDir, os.FileMode(0700))
	if err != nil {
		return wrapErrorf(`cannot create the directory "%s": %w`, keysDir, err)
	}
	if _, err := os.Stat(filepath.Join(keysDir, privateFileName)); os.IsNotExist(err) {
		return i.generateAndSaveKeys(keysDir)
	}
	err = i.loadKeys(keysDir)
	if err == nil {
		if _, checkErr := os.Stat(filepath.Join(keysDir, publicFileName)); os.IsNotExist(checkErr) {
			err = i.savePublicKey(keysDir)
		}
	}
	if err != nil {
		return newErrCannotLoadKeys(err)
	}
	return nil
}

func (i *Identity) NewSession(
	ctx context.Context,
	remoteIdentity *Identity,
	backend io.ReadWriteCloser,
	eventHandler EventHandler,
	opts *SessionOptions,
) *Session {
	return newSession(ctx, i, remoteIdentity, backend, eventHandler, opts)
}

func (i *Identity) MutualConfirmationOfIdentity(
	ctx context.Context,
	remoteIdentity *Identity,
	backend io.ReadWriteCloser,
	eventHandler EventHandler,
	options *SessionOptions,
) (xerr error, ephemeralKey []byte) {
	var n int

	var opts SessionOptions
	if options != nil {
		opts = *options
	}

	// Detach from `backend` right after the first authentication message.
	opts.DetachOnSequentialDecryptFailsCount = 1
	opts.DetachOnMessagesCount = 1

	var decryptError error
	sess := newSession(
		ctx,
		i,
		remoteIdentity,
		backend,
		wrapErrorHandler(eventHandler, func(sess *Session, err error) bool {
			if errors.As(err, &ErrCannotDecrypt{}) {
				decryptError = err
			}
			if eventHandler.IsDebugEnabled() {
				eventHandler.Debugf(`closing the backend due to %v`, err)
			}
			_ = sess.Close()
			return false
		}),
		&opts,
	)
	defer func() {
		_ = sess.Close()
		sess.WaitForClosure()
	}()

	n, err := sess.Write(i.Keys.Public)
	if err != nil {
		xerr = wrapErrorf(`unable to write via a session: %w`, err)
		return
	}
	if n != len(i.Keys.Public) {
		xerr = wrapErrorf(`unable to send my public key: %w`, newErrPartialWrite())
		return
	}

	remotePubKey := make([]byte, len(remoteIdentity.Keys.Public))
	n, err = sess.Read(remotePubKey)
	if err != nil {
		xerr = wrapErrorf(`unable to read data via session: %w`, err)
		return
	}
	if decryptError != nil {
		xerr = wrapErrorf(`unable to decrypt: %w`, decryptError)
		return
	}
	if n != len(i.Keys.Public) {
		xerr = newErrWrongKeyLength(uint(len(i.Keys.Public)), uint(n))
		return
	}

	if bytes.Compare(remoteIdentity.Keys.Public, remotePubKey) != 0 {
		xerr = newErrInvalidSignature()
		return
	}

	ephemeralKey = sess.GetEphemeralKey()
	return
}

func (i *Identity) VerifySignature(signature, data []byte) error {
	if !ed25519.Verify(i.Keys.Public, data, signature) {
		return newErrInvalidSignature()
	}
	return nil
}

func (i *Identity) Sign(signature, data []byte) {
	result := ed25519.Sign(i.Keys.Private, data)
	copy(signature, result)
}
