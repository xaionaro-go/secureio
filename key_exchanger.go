package secureio

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/aead/ecdh"
	xerrors "github.com/xaionaro-go/errors"
	"golang.org/x/crypto/sha3"
)

const (
	// DefaultKeyExchangeInterval defines how ofter the cipher key is renewed.
	DefaultKeyExchangeInterval = time.Minute

	// DefaultKeyExchangeTimeout defines how long it will wait (after sending
	// the request) for a response to request to exchange keys before
	// consider the situation erroneous.
	DefaultKeyExchangeTimeout = time.Minute
)

const (
	// PublicKeySize the size of a identity public key in bytes.
	PublicKeySize = ed25519.PublicKeySize

	// PrivateKeySize the size of a identity private key in bytes
	PrivateKeySize = ed25519.PrivateKeySize

	// keySignatureSize the size of signature of a public key in bytes
	keySignatureSize = ed25519.SignatureSize

	curve25519PrivateKeySize = 32
	curve25519PublicKeySize  = 32
)

var (
	binaryOrderType = binary.LittleEndian

	// Salt is used to append PSKs. If you change this value then
	// it is required to change it on both sides.
	Salt = []byte(`xaionaro-go/secureio.KeyExchanger`)
)

type keyExchanger struct {
	locker sync.Mutex

	ctx        context.Context
	cancelFunc func()
	okFunc     func([]byte)
	errFunc    func(error)
	options    KeyExchangerOptions

	failCount                  uint
	lastExchangeTS             time.Time
	nextLocalKeyLocker         lockerRWMutex
	nextLocalPrivateKey        *[curve25519PrivateKeySize]byte
	nextLocalPublicKey         *[curve25519PublicKeySize]byte
	remoteKeySeedUpdateMessage keySeedUpdateMessage
	localKeySeedUpdateMessage  keySeedUpdateMessage
	localIdentity              *Identity
	remoteIdentity             *Identity
	messenger                  *Messenger
	ecdh                       ecdh.KeyExchange
}

// KeyExchangerOptions is used to configure the key exchanging options.
// It's passed to a session via SessionOptions.
type KeyExchangerOptions struct {
	// Interval defines delay between generating a new cipher key.
	//
	// Generating a key is an expensive operation. Moreover
	// secureio remembers only the current key and the previous one. So
	// if you generate keys with interval less than required for stable
	// round-trip between peers, then the session will be very unstable.
	//
	// If a zero-value then DefaultKeyExchangeInterval is used.
	Interval time.Duration

	// Timeout defines how long it can wait after sending a request
	// to exchange keys and before the successful key exchange. If
	// it waits more than the timeout then an error is returned.
	//
	// If a zero-value then DefaultKeyExchangeTimeout is used.
	Timeout time.Duration

	// PSK is a Pre-Shared Key. If it is set then it is used as
	// an additional source for ephemeral key ("cipher key") generation.
	// So if it is set then to initiate a working session it's required to
	// satisfy both conditions: valid (and expected) identities and the same PSK.
	PSK []byte
}

func newKeyExchanger(
	ctx context.Context,
	localIdentity *Identity,
	remoteIdentity *Identity,
	messenger *Messenger,
	okFunc func([]byte), errFunc func(error),
	opts *KeyExchangerOptions,
) *keyExchanger {
	kx := &keyExchanger{
		okFunc:         okFunc,
		errFunc:        errFunc,
		localIdentity:  localIdentity,
		remoteIdentity: remoteIdentity,
		messenger:      messenger,
		ecdh:           ecdh.X25519(),
	}

	if opts != nil {
		kx.options = *opts
	}
	if kx.options.Interval == 0 {
		kx.options.Interval = DefaultKeyExchangeInterval
	}
	if kx.options.Timeout == 0 {
		kx.options.Timeout = DefaultKeyExchangeTimeout
	}

	kx.ctx, kx.cancelFunc = context.WithCancel(ctx)
	messenger.SetHandler(kx)
	kx.start()
	return kx
}

func (kx *keyExchanger) LockDo(fn func()) {
	kx.locker.Lock()
	defer kx.locker.Unlock()
	fn()
}

func (kx *keyExchanger) generateSharedKey(
	localPrivateKey *[curve25519PrivateKeySize]byte,
	remotePublicKey *[curve25519PublicKeySize]byte,
) ([]byte, error) {
	key := kx.ecdh.ComputeSecret(localPrivateKey, remotePublicKey)

	psk := kx.options.PSK
	if len(psk) > 0 {
		pskWithSalt := make([]byte, 0, len(psk)+len(Salt))
		pskWithSalt = append(pskWithSalt, psk...)
		pskWithSalt = append(pskWithSalt, Salt...)
		pskHash := sha3.Sum256(pskWithSalt)
		for i := 0; i < len(pskHash); i++ {
			key[i] ^= pskHash[i]
		}
	}

	return key, nil
}

func (kx *keyExchanger) isDone() bool {
	select {
	case <-kx.ctx.Done():
		return true
	default:
		return false
	}
}

func (kx *keyExchanger) Handle(b []byte) (err error) {
	var nextLocal *[curve25519PrivateKeySize]byte
	kx.nextLocalKeyLocker.RLockDo(func() {
		nextLocal = kx.nextLocalPrivateKey
	})
	kx.LockDo(func() {
		defer func() { err = wrapError(err) }()

		msg := &kx.remoteKeySeedUpdateMessage
		err = binary.Read(bytes.NewBuffer(b), binaryOrderType, msg)
		if err != nil {
			return
		}
		if err = kx.remoteIdentity.VerifySignature(msg.Signature[:], msg.PublicKey[:]); err != nil {
			kx.messenger.sess.debugf("wrong signature: %v", err)
			return
		}
		if nextLocal == nil {
			return // Not ready, yet. It's required to call UpdateKey(), first
		}
		nextRemote := &msg.PublicKey
		nextKey, genErr := kx.generateSharedKey(nextLocal, nextRemote)
		if genErr != nil {
			_ = kx.Close()
			if !errors.As(genErr, &ErrAlreadyClosed{}) || !kx.isDone() {
				kx.errFunc(wrapError(genErr))
			}
			return
		}
		kx.okFunc(nextKey)
		kx.lastExchangeTS = time.Now()
	})
	return
}

func (kx *keyExchanger) Close() error {
	kx.stop()
	kx.messenger.sess.debugf("key exchanger closed")
	return nil
}

func (kx *keyExchanger) stop() {
	kx.cancelFunc()
}

func (kx *keyExchanger) start() {
	kx.UpdateKey()
	kx.iterate()
	go kx.loop()
}

func (kx *keyExchanger) iterate() {
	kx.messenger.sess.debugf("kx.iterate()")

	var lastExchangeTS time.Time
	kx.LockDo(func() {
		lastExchangeTS = kx.lastExchangeTS
	})
	now := time.Now()
	if !lastExchangeTS.IsZero() &&
		now.Sub(lastExchangeTS) < kx.options.Interval {
		return
	}
	if !lastExchangeTS.IsZero() &&
		now.Sub(lastExchangeTS) > kx.options.Interval+kx.options.Timeout {
		_ = kx.Close()
		kx.errFunc(newErrKeyExchangeTimeout())
		return
	}
	err := kx.sendPublicKey()
	if err != nil {
		_ = kx.Close()
		kx.errFunc(xerrors.Errorf("unable to send a public key: %w", err))
		return
	}
}

func (kx *keyExchanger) loop() {
	sendPublicKeyTicker := time.NewTicker(time.Second)
	defer sendPublicKeyTicker.Stop()
	for {
		select {
		case <-kx.ctx.Done():
			_ = kx.messenger.Close()
			return
		case <-sendPublicKeyTicker.C:
			kx.iterate()
		}
	}
}

func (kx *keyExchanger) sendPublicKey() error {
	kx.messenger.sess.debugf("kx.sendPublicKey()")
	msg := &kx.localKeySeedUpdateMessage
	copy(msg.PublicKey[:], (*kx.nextLocalPublicKey)[:])
	kx.localIdentity.Sign(msg.Signature[:], msg.PublicKey[:])
	return kx.send(msg)
}

func (kx *keyExchanger) UpdateKey() {
	privKey, pubKey, err := kx.ecdh.GenerateKey(rand.Reader)
	if err != nil {
		_ = kx.Close()
		kx.errFunc(xerrors.Errorf("unable to generate ECDH keys: %w", err))
		return
	}
	privKeyCasted := privKey.([curve25519PrivateKeySize]byte)
	pubKeyCasted := pubKey.([curve25519PublicKeySize]byte)
	kx.nextLocalKeyLocker.LockDo(func() {
		kx.nextLocalPrivateKey = &privKeyCasted
		kx.nextLocalPublicKey = &pubKeyCasted
	})
	return
}

func (kx *keyExchanger) send(msg *keySeedUpdateMessage) error {
	err := binary.Write(kx.messenger, binaryOrderType, msg)
	if err != nil {
		return xerrors.Errorf("unable to send keySeedUpdateMessage: %w", err)
	}
	return nil
}
