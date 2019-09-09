package secureio

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"

	xerrors "github.com/xaionaro-go/errors"
)

const (
	//authorizedKeysFileName = `authorized_keys`
	publicFileName  = `id_ed25519`
	privateFileName = `id_ed25519.pub`
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
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
		return err
	}

	keyBlock := pem.Block{
		Type:    keyType,
		Headers: nil,
		Bytes:   key,
	}

	return pem.Encode(keyFile, &keyBlock)
}

func (i *Identity) generateAndSaveKeys(keysDir string) error {
	var err error
	i.Keys.Public, i.Keys.Private, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Wrap(err, "Cannot generate keys")
	}
	err = i.savePrivateKey(keysDir)
	if err == nil {
		err = i.savePublicKey(keysDir)
	}
	return errors.Wrap(err, "Cannot save keys")
}

func loadPublicKeyFromFile(keyPtr *ed25519.PublicKey, path string) error {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(keyBytes)
	if len(block.Bytes) != ed25519.PublicKeySize {
		return fmt.Errorf("Read key is of wrong length: %d != %d", len(block.Bytes), ed25519.PublicKeySize)
	}
	*keyPtr = block.Bytes
	return nil
}

func loadPrivateKeyFromFile(keyPtr *ed25519.PrivateKey, path string) error {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(keyBytes)
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("Read key is of wrong length: %d != %d", len(block.Bytes), ed25519.PrivateKeySize)
	}
	*keyPtr = block.Bytes
	return nil
}

func (i *Identity) loadKeys(keysDir string) error {
	err := loadPrivateKeyFromFile(&i.Keys.Private, filepath.Join(keysDir, privateFileName))
	if err != nil {
		return errors.Wrap(err, "Cannot load the private key")
	}
	i.Keys.Public = i.Keys.Private.Public().(ed25519.PublicKey)
	return nil
}

func (i *Identity) prepareKeys(keysDir string) error {
	err := os.MkdirAll(keysDir, os.FileMode(0700))
	if err != nil {
		return errors.Wrap(err, "Cannot create the directory: "+keysDir)
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
	return errors.Wrap(err, "Cannot load keys")
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
) (err error, ephemeralKey []byte) {
	var n int

	var opts SessionOptions
	if options != nil {
		opts = *options
	}
	opts.ErrorOnSequentialDecryptFailsCount = &[]uint{1}[0]
	opts.DetachOnMessagesCount = 1

	sess := newSession(
		ctx,
		i,
		remoteIdentity,
		backend,
		wrapErrorHandler(eventHandler, func(sess *Session, err error) {
			xerr := err.(*xerrors.Error)
			if !xerr.Has(ErrCannotDecrypt) {
				err = xerr
			}
			sess.Close()
		}),
		&opts,
	)

	n, err = sess.Write(i.Keys.Public)
	if err != nil {
		return
	}
	if n != len(i.Keys.Public) {
		err = errors.Wrap(ErrPartialWrite, `unable to send my public key`)
		return
	}

	remotePubKey := make([]byte, len(remoteIdentity.Keys.Public))
	n, err = sess.Read(remotePubKey)
	if err != nil {
		return
	}
	if n != len(i.Keys.Public) {
		err = errors.Wrap(ErrInvalidLength, `unable to receive remote public key`)
		return
	}

	if bytes.Compare(remoteIdentity.Keys.Public, remotePubKey) != 0 {
		err = errors.Wrap(ErrInvalidSignature, `unexpected error`)
		return
	}

	ephemeralKey = sess.GetEphemeralKey()
	sess.Close()
	sess.WaitForClosure()
	return
}

func (i *Identity) VerifySignature(signature, data []byte) error {
	if !ed25519.Verify(i.Keys.Public, data, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func (i *Identity) Sign(signature, data []byte) {
	result := ed25519.Sign(i.Keys.Private, data)
	copy(signature, result)
}
