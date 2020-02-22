package secureio

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"time"

	"github.com/aead/ecdh"
	"golang.org/x/crypto/sha3"

	xerrors "github.com/xaionaro-go/errors"
)

const (
	// DefaultKeyExchangeInterval defines how ofter the cipher key is renewed.
	DefaultKeyExchangeInterval = time.Minute

	// DefaultKeyExchangeTimeout defines how long it will wait (after sending
	// the request) for a response to request to exchange keys before
	// consider the situation erroneous.
	DefaultKeyExchangeTimeout = time.Minute

	// DefaultKeyExchangeRetryInterval defines the default value of
	// KeyExchangerOptions.RetryInterval.
	DefaultKeyExchangeRetryInterval = time.Second
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
	locker sync.RWMutex

	ctx           context.Context
	cancelFunc    func()
	setSecretFunc func([]byte)
	doneFunc      func()
	errFunc       func(error)
	options       KeyExchangerOptions

	failCount                  uint
	lastExchangeTS             time.Time
	nextLocalKeyLocker         lockerRWMutex
	nextLocalPrivateKey        *[curve25519PrivateKeySize]byte
	nextLocalPublicKey         *[curve25519PublicKeySize]byte
	remoteKeySeedUpdateMessage keySeedUpdateMessage
	localIdentity              *Identity
	remoteIdentity             *Identity
	messenger                  *Messenger
	ecdh                       ecdh.KeyExchange

	keyID             uint64
	nextKeyID         uint64
	successNotifyChan chan uint64
	keyUpdateLocker   lockerRWMutex
}

// KeyExchangerOptions is used to configure the key exchanging options.
// It's passed to a session via SessionOptions.
type KeyExchangerOptions struct {
	// KeyUpdateInterval defines delay between generating a new cipher key.
	//
	// Generating a key is an expensive operation. Moreover
	// secureio remembers only the current key and the previous one. So
	// if you generate keys with interval less than required for stable
	// round-trip between peers, then the session will be very unstable.
	//
	// If a zero-value then DefaultKeyExchangeInterval is used.
	KeyUpdateInterval time.Duration

	// RetryInterval defines the maximal delay between sending a key exchange
	// packet and success key exchange before resending the key exchange
	// packet.
	//
	// If a zero-value then DefaultKeyExchangeRetryInterval is used instead.
	RetryInterval time.Duration

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

	// AnswerMode set the behavior of key-exchange message acknowledgments.
	//
	// When the local side receives a packet from the remote side it _may_
	// send a key exchange packet even if it was already sent before. This
	// packet is called "answer". An answer packet is marked with a special
	// flag to prevent answers on answers (to prevent loops).
	//
	// If two parties has different AnswersModes then an error will be
	// reported.
	//
	// See KeyExchangeAnswersMode values.
	AnswersMode KeyExchangeAnswersMode
}

// KeyExchangeAnswersMode is the variable type for KeyExchangeOptions.AnswerMode
type KeyExchangeAnswersMode uint8

const (
	// KeyExchangeAnswersModeDefault means use the default value of AnswerMode
	KeyExchangeAnswersModeDefault = KeyExchangeAnswersMode(iota)

	// KeyExchangeAnswersModeAnswerAndWait makes the key exchanger to send
	// answers and wait for answers from the remote side before consider
	// a key exchange to be successful.
	KeyExchangeAnswersModeAnswerAndWait

	// KeyExchangeAnswersModeAnswer makes the key exchanger to send
	// answers, but don't wait for them from the remote side.
	KeyExchangeAnswersModeAnswer

	// KeyExchangeAnswersModeDisable makes the key exchanger to do not
	// send answers and to do not wait for them from the remote side.
	KeyExchangeAnswersModeDisable
)

func newKeyExchanger(
	ctx context.Context,
	localIdentity *Identity,
	remoteIdentity *Identity,
	messenger *Messenger,
	setSecretFunc func([]byte),
	doneFunc func(),
	errFunc func(error),
	opts *KeyExchangerOptions,
) *keyExchanger {
	kx := &keyExchanger{
		setSecretFunc:     setSecretFunc,
		doneFunc:          doneFunc,
		errFunc:           errFunc,
		localIdentity:     localIdentity,
		remoteIdentity:    remoteIdentity,
		messenger:         messenger,
		ecdh:              ecdh.X25519(),
		successNotifyChan: make(chan uint64),
	}

	if opts != nil {
		kx.options = *opts
	}
	if kx.options.KeyUpdateInterval == 0 {
		kx.options.KeyUpdateInterval = DefaultKeyExchangeInterval
	}
	if kx.options.RetryInterval == 0 {
		kx.options.RetryInterval = DefaultKeyExchangeRetryInterval
	}
	if kx.options.Timeout == 0 {
		kx.options.Timeout = DefaultKeyExchangeTimeout
	}
	if kx.options.AnswersMode == KeyExchangeAnswersModeDefault {
		kx.options.AnswersMode = KeyExchangeAnswersModeAnswerAndWait
	}

	kx.ctx, kx.cancelFunc = context.WithCancel(ctx)
	go func() {
		<-kx.ctx.Done()
		close(kx.successNotifyChan)
	}()
	messenger.SetHandler(kx)
	kx.start()
	return kx
}

func (kx *keyExchanger) RLockDo(fn func()) {
	kx.locker.RLock()
	defer kx.locker.RUnlock()
	fn()
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
			kx.messenger.sess.debugf("[kx] wrong signature: %v", err)
			return
		}
		if nextLocal == nil {
			return // Not ready, yet. It's required to call KeyUpdateSendWait(), first
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

		if msg.AnswersMode != kx.options.AnswersMode {
			kx.errFunc(newErrAnswersModeMismatch(kx.options.AnswersMode, msg.AnswersMode))
		}

		kx.messenger.sess.debugf("[kx] set the secret")
		kx.setSecretFunc(nextKey)
		if msg.Flags.IsAnswer() || kx.options.AnswersMode != KeyExchangeAnswersModeAnswerAndWait {
			kx.lastExchangeTS = time.Now()
			kx.sendSuccessNotifications()
		}

		if !msg.Flags.IsAnswer() && kx.options.AnswersMode != KeyExchangeAnswersModeDisable {
			go func() {
				kx.mustSendPublicKey(true)
			}()
		}
	})
	return
}

func (kx *keyExchanger) sendSuccessNotifications() {
	var nextKeyID uint64
	kx.nextLocalKeyLocker.RLockDo(func() {
		nextKeyID = kx.nextKeyID
		kx.keyID = nextKeyID
	})
	func() {
		defer func() { recover() }() // just in case; TODO: remove this line
		select {
		case <-kx.ctx.Done():
		case kx.successNotifyChan <- nextKeyID:
		default:
		}
	}()
	kx.messenger.sess.debugf("[kx] a successful key exchange, keyID == %v", nextKeyID)

	kx.doneFunc()
}

func (kx *keyExchanger) Close() error {
	kx.stop()
	kx.messenger.sess.debugf("[kx] key exchanger closed")
	return nil
}

func (kx *keyExchanger) stop() {
	kx.cancelFunc()
}

func (kx *keyExchanger) start() {
	kx.messenger.sess.debugf("[kx] kx.start()")
	go kx.loop()
}

func (kx *keyExchanger) loop() {
	kx.KeyUpdateSendWait()

	keyUpdateTicker := time.NewTicker(kx.options.KeyUpdateInterval)
	defer keyUpdateTicker.Stop()

	for {
		select {
		case <-kx.ctx.Done():
			_ = kx.messenger.Close()
			return
		case <-keyUpdateTicker.C:
			kx.KeyUpdateSendWait()
		}
	}
}

func (kx *keyExchanger) mustSendPublicKey(isAnswer bool) {
	err := kx.sendPublicKey(isAnswer)
	if err != nil {
		_ = kx.Close()
		kx.errFunc(xerrors.Errorf("[kx] unable to send a public key: %w", err))
	}
}

func (kx *keyExchanger) sendPublicKey(isAnswer bool) error {
	kx.messenger.sess.debugf("[kx] kx.sendPublicKey(isAnswer: %v)", isAnswer)
	msg := &keySeedUpdateMessage{}
	kx.nextLocalKeyLocker.RLockDo(func() {
		copy(msg.PublicKey[:], (*kx.nextLocalPublicKey)[:])
	})
	kx.localIdentity.Sign(msg.Signature[:], msg.PublicKey[:])
	msg.Flags.SetIsAnswer(isAnswer)
	msg.AnswersMode = kx.options.AnswersMode
	return kx.send(msg)
}

func (kx *keyExchanger) updateKey() (result uint64) {
	var isAlreadyInProgress bool
	kx.nextLocalKeyLocker.RLockDo(func() {
		isAlreadyInProgress = kx.nextKeyID > kx.keyID
	})
	if isAlreadyInProgress {
		panic("isAlreadyInProgress")
	}

	privKey, pubKey, err := kx.ecdh.GenerateKey(rand.Reader)
	if err != nil {
		_ = kx.Close()
		kx.errFunc(xerrors.Errorf("[kx] unable to generate ECDH keys: %w", err))
		return 0
	}
	privKeyCasted := privKey.([curve25519PrivateKeySize]byte)
	pubKeyCasted := pubKey.([curve25519PublicKeySize]byte)
	kx.nextLocalKeyLocker.LockDo(func() {
		kx.nextLocalPrivateKey = &privKeyCasted
		kx.nextLocalPublicKey = &pubKeyCasted
		kx.nextKeyID = kx.keyID + 1
		result = kx.nextKeyID
	})

	return
}

func (kx *keyExchanger) KeyUpdateSendWait() {
	kx.messenger.sess.debugf("[kx] KeyUpdateSendWait")
	kx.keyUpdateLocker.LockDo(func() {
		// Empty the chan (to wait for our event only on retries)
		for {
			select {
			case <-kx.ctx.Done():
				return
			case _, ok := <-kx.successNotifyChan:
				if !ok {
					return
				}
				continue
			default:
			}
			break
		}

		// Update the key (and increase nextKeyID)
		nextKeyID := kx.updateKey()
		kx.messenger.sess.debugf("[kx] nextKeyID == %v", nextKeyID)
		if nextKeyID == 0 {
			return
		}

		// Send
		kx.mustSendPublicKey(false)

		// Retries:
		timeoutTimer := time.NewTimer(kx.options.Timeout)
		retryTicker := time.NewTicker(kx.options.RetryInterval)
		defer retryTicker.Stop()
		for {
			select {
			case <-kx.ctx.Done():
				kx.messenger.sess.debugf("[kx] KeyUpdateSendWait: done")
				return
			case newKeyID, ok := <-kx.successNotifyChan:
				kx.messenger.sess.debugf("[kx] KeyUpdateSendWait: success (keyID == %v)", newKeyID)
				if !ok {
					return
				}
				if newKeyID > nextKeyID {
					panic(`newKeyID > nextKeyID`)
				}
				if newKeyID == nextKeyID {
					return
				}
			case <-retryTicker.C:
				kx.messenger.sess.debugf("[kx] KeyUpdateSendWait: retry (waiting for keyID == %v)", nextKeyID)
				runtime.Gosched()
				kx.mustSendPublicKey(false)
			case <-timeoutTimer.C:
				kx.messenger.sess.debugf("[kx] KeyUpdateSendWait: timeout")
				_ = kx.Close()
				kx.errFunc(newErrKeyExchangeTimeout())
				return
			}
		}
	})
}

func (kx *keyExchanger) send(msg *keySeedUpdateMessage) error {
	err := binary.Write(kx.messenger, binaryOrderType, msg)
	if err != nil {
		return xerrors.Errorf("unable to send keySeedUpdateMessage: %w", err)
	}
	return nil
}
