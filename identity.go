package secureio

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	xerrors "github.com/xaionaro-go/errors"
)

const (
	//authorizedKeysFileName = `authorized_keys`
	publicFileName  = `id_ed25519`
	privateFileName = `id_ed25519.pub`
)

// Keys is a key pair used to generate signatures (to be verified on
// the remote side) and to verify the remote side.
//
// If "Private" key is defined than it could be used for a local identity
// If "Public" key is defined than it could be used for a remote identity.
type Keys struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// Identity is a subject of a (secure) communication. Identity is used to
// be identified as the subject that is expected to be communicating with.
//
// If the "Private" key is set then the identity could be used as a "local
// identity", so it could be used to represent the communication participant
// to a remote side.
//
// If the "Public" key is set then the identity could be used as a "remote
// identity", so it could be used to verify the communication participant
// of the remote side.
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

// NewIdentity is a constructor for `Identity` based on the path
// to ED25519 keys. It:
//
// * Parses ED25519 keys from directory `keysDir` if they exists
// and creates a new instance of `*Identity`.
// * Creates ED25510 keys and saves them to the directory `keysDir` if they
// does not exist there and creates a new instance of `*Identity`.
//
// File names in the directory are `id_ed25519` and `id_ed25519.pub`.
//
// The returned identity (if it is not `nil`) could be
// used as both: local and remote (see `Identity`).
func NewIdentity(keysDir string) (*Identity, error) {
	i := &Identity{}
	return i, i.prepareKeys(keysDir)
}

// NewIdentityFromPrivateKey is a constructor for `Identity` based
// on private ED25519 key.
//
// The returned identity could be used as both: local and remote
// (see `Identity`).
func NewIdentityFromPrivateKey(privKey ed25519.PrivateKey) *Identity {
	i := &Identity{}
	i.Keys.Private = privKey
	i.Keys.Public = privKey.Public().(ed25519.PublicKey)
	return i
}

// NewRemoteIdentity is a constructor for `Identity` based on the path
// to the ED25519 public key. It parses the public key from the directory
// `keysDir`. The file name is `id_ed25519.pub`.
//
// The returned identity (if it is not `nil`) could be
// used only as a remote identity (see `Identity`).
func NewRemoteIdentity(keyPath string) (*Identity, error) {
	i := &Identity{}
	return i, loadPublicKeyFromFile(&i.Keys.Public, keyPath)
}

// NewRemoteIdentityFromPublicKey is a constructor for `Identity` based on
// the ED25519 public key.
//
// The returned identity could be used only as a remote identity
// (see `Identity`).
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
		return xerrors.Errorf("unable to open file: %w", err)
	}

	keyBlock := pem.Block{
		Type:    keyType,
		Headers: nil,
		Bytes:   key,
	}

	err = pem.Encode(keyFile, &keyBlock)
	if err != nil {
		return xerrors.Errorf("pem.Encode() returned an error: %w", err)
	}

	return nil
}

func (i *Identity) generateAndSaveKeys(keysDir string) error {
	var err error
	i.Keys.Public, i.Keys.Private, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return xerrors.Errorf("cannot generate keys: %w", err)
	}
	err = i.savePrivateKey(keysDir)
	if err == nil {
		err = i.savePublicKey(keysDir)
	}
	if err != nil {
		return xerrors.Errorf("cannot save keys: %w", err)
	}
	return nil
}

func loadPublicKeyFromFile(keyPtr *ed25519.PublicKey, path string) error {
	keyBytes, err := ioutil.ReadFile(path) // #nosec
	if err != nil {
		return xerrors.Errorf("unable to read key: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if len(block.Bytes) != ed25519.PublicKeySize {
		return newErrWrongKeyLength(ed25519.PublicKeySize, uint(len(block.Bytes)))
	}
	*keyPtr = block.Bytes
	return nil
}

func loadPrivateKeyFromFile(keyPtr *ed25519.PrivateKey, path string) error {
	keyBytes, err := ioutil.ReadFile(path) // #nosec
	if err != nil {
		return xerrors.Errorf("unable to read file: %w", err)
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
		return xerrors.Errorf("Cannot load the private key: %w", err)
	}
	i.Keys.Public = i.Keys.Private.Public().(ed25519.PublicKey)
	return nil
}

func (i *Identity) prepareKeys(keysDir string) error {
	err := os.MkdirAll(keysDir, os.FileMode(0700))
	if err != nil {
		return xerrors.Errorf(`cannot create the directory "%s": %w`, keysDir, err)
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

// NewSession creates a secure session over (unsecure) `backend`.
//
// The session verifies the remote side using `remoteIdentity`,
// securely exchanges with encryption keys and allows
// to communicate through it.
// Nothing else should write-to or/and read-from the `backend` while
// the session is active.
//
// See `Session`.
func (i *Identity) NewSession(
	ctx context.Context,
	remoteIdentity *Identity,
	backend io.ReadWriteCloser,
	eventHandler EventHandler,
	opts *SessionOptions,
) *Session {
	return newSession(ctx, i, remoteIdentity, backend, eventHandler, opts)
}

// MutualConfirmationOfIdentity is a helper which creates a temporary
// session to verify the remote side and (securely) exchange
// with an ephemeral key.
// If this method is used then it should be used on the both sides.
// While an execution of the method nothing else should write-to
// or/and read-from the `backend`.
// By the end of execution of this method the temporary session will be closed
// and then the backend will be free to be used for other purposes.
//
// This method could be used for example to:
// * Verify if the expected participant is on the remote side.
// * Easy and securely create a new shared key with the remote side.
func (i *Identity) MutualConfirmationOfIdentity(
	ctx context.Context,
	remoteIdentity *Identity,
	backend io.ReadWriteCloser,
	eventHandler EventHandler,
	options *SessionOptions,
) (ephemeralKey []byte, xerr error) {
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
			sess.debugf(`closing the backend due to %v`, err)
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
		xerr = xerrors.Errorf(`unable to write via a session: %w`, err)
		return
	}
	if n != len(i.Keys.Public) {
		xerr = xerrors.Errorf(`unable to send my public key: %w`, newErrPartialWrite())
		return
	}

	remotePubKey := make([]byte, len(remoteIdentity.Keys.Public))
	n, err = sess.Read(remotePubKey)
	if err != nil {
		xerr = xerrors.Errorf(`unable to read data via session: %w`, err)
		return
	}
	if decryptError != nil {
		xerr = xerrors.Errorf(`unable to decrypt: %w`, decryptError)
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

// VerifySignature just verifies an ED25519 signature `signature` over `data`.
func (i *Identity) VerifySignature(signature, data []byte) error {
	if !ed25519.Verify(i.Keys.Public, data, signature) {
		return newErrInvalidSignature()
	}
	return nil
}

// Sign just fills `signature` with an ED25519 signature of `data`.
func (i *Identity) Sign(signature, data []byte) {
	result := ed25519.Sign(i.Keys.Private, data)
	copy(signature, result)
}
