package secureio

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/aead/ecdh"
	"github.com/xaionaro-go/bytesextra"
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
	// LittleEndian is the most popular architecture family, so
	// to preserve more performance in the most cases we is it:
	binaryOrderType = binary.LittleEndian

	// Salt is used to append PSKs. If you change this value then
	// it is required to change it on both sides.
	Salt = []byte(`xaionaro-go/secureio.KeyExchanger`)
)

type secretID uint

const (
	secretIDRecentBoth = secretID(iota)
	secretIDRecentLocal
	secretIDRecentRemote
	secretIDPrevious

	_secretIDs
	secretIDs = int(_secretIDs)
)

type keyExchanger struct {
	locker sync.RWMutex

	ctx            context.Context
	cancelFunc     func()
	setSecretsFunc func([][]byte)
	doneFunc       func()
	errFunc        func(error)
	options        KeyExchangerOptions

	failCount           uint
	lastExchangeTS      time.Time
	keyLocker           lockerRWMutex
	prevRemotePublicKey *[curve25519PublicKeySize]byte
	nextRemotePublicKey *[curve25519PublicKeySize]byte
	prevLocalPrivateKey *[curve25519PrivateKeySize]byte
	nextLocalPrivateKey *[curve25519PrivateKeySize]byte
	nextLocalPublicKey  *[curve25519PublicKeySize]byte
	localIdentity       *Identity
	remoteIdentity      *Identity
	messenger           *Messenger
	ecdh                ecdh.KeyExchange

	remoteSessionID       *SessionID
	remoteKeyID           uint64
	localKeyCreatedAt     uint64
	nextLocalKeyCreatedAt uint64
	successNotifyChan     chan uint64
	keyUpdateLocker       lockerRWMutex
	skipKeyUpdateUntil    time.Time
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

	// maximalTimeDifference enables check of how sane are timestamps
	// are being received from the remote side. If the timestamp
	// is from far past or from far future it may be considered as
	// a hack attempt.
	//
	// By default this check is disabled. To enable it set
	// a non-zero value. The value defines how big could be the
	// legitimate difference between local clock and remote clock.
	// The time difference should include possible network delays.
	maximalTimeDifference time.Duration

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

	// AnswersMode set the behavior of key-exchange message acknowledgments.
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

// KeyExchangeAnswersMode is the variable type for KeyExchangeOptions.AnswersMode
type KeyExchangeAnswersMode uint8

const (
	// KeyExchangeAnswersModeDefault means use the default value of AnswersMode
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
	setSecretsFunc func([][]byte),
	doneFunc func(),
	errFunc func(error),
	opts *KeyExchangerOptions,
) *keyExchanger {
	kx := &keyExchanger{
		setSecretsFunc:    setSecretsFunc,
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
	if localPrivateKey == nil {
		return nil, newErrLocalPrivateKeyIsNil()
	}
	if remotePublicKey == nil {
		return nil, newErrRemotePublicKeyIsNil()
	}

	key := kx.ecdh.ComputeSecret(localPrivateKey, remotePublicKey)
	var zeroKey [32]byte
	if bytes.Compare(key, zeroKey[:]) == 0 {
		panic(fmt.Sprintf("should not happen: %v %v", localPrivateKey, remotePublicKey))
	}

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

func (kx *keyExchanger) updateSecrets() (err error) {
	defer func() { err = wrapError(err) }()

	var prevRemote *[curve25519PublicKeySize]byte
	var nextRemote *[curve25519PublicKeySize]byte
	var prevLocal *[curve25519PrivateKeySize]byte
	var nextLocal *[curve25519PrivateKeySize]byte
	kx.keyLocker.RLockDo(func() {
		prevRemote = kx.prevRemotePublicKey
		nextRemote = kx.nextRemotePublicKey
		prevLocal = kx.prevLocalPrivateKey
		nextLocal = kx.nextLocalPrivateKey
	})

	newSecrets := make([][]byte, secretIDs)
	for secretIdx := 0; secretIdx < secretIDs; secretIdx++ {
		var genErr error
		var newSecret []byte
		switch secretID(secretIdx) {
		case secretIDRecentBoth:
			newSecret, genErr = kx.generateSharedKey(nextLocal, nextRemote)
		case secretIDRecentLocal:
			newSecret, genErr = kx.generateSharedKey(nextLocal, prevRemote)
		case secretIDRecentRemote:
			newSecret, genErr = kx.generateSharedKey(prevLocal, nextRemote)
		case secretIDPrevious:
			newSecret, genErr = kx.generateSharedKey(prevLocal, prevRemote)
		}
		if genErr != nil &&
			!errors.As(genErr, &errLocalPrivateKeyIsNil{}) &&
			!errors.As(genErr, &errRemotePublicKeyIsNil{}) {
			return genErr
		}
		newSecrets[secretIdx] = newSecret
	}

	kx.messenger.sess.debugf("[kx] set the secrets")
	kx.setSecretsFunc(newSecrets)
	return nil
}

func (kx *keyExchanger) Handle(b []byte) (err error) {
	defer func() { err = wrapError(err) }()

	if len(b) < keySeedUpdateMessageSignedSize {
		return newErrTooShort(uint(keySeedUpdateMessageSignedSize), uint(len(b)))
	}

	signature := b[:keySignatureSize]
	msgBytes := b[keySignatureSize:keySeedUpdateMessageSignedSize]
	if len(b) > keySeedUpdateMessageSignedSize {
		kx.messenger.sess.debugf("[kx] ignored the tail of length %v", keySeedUpdateMessageSignedSize-len(b))
	}
	if err = kx.remoteIdentity.VerifySignature(signature, msgBytes); err != nil {
		kx.messenger.sess.debugf("[kx] ignoring the message due to the wrong signature: %v", err)
		return
	}

	var msg keySeedUpdateMessage
	err = binary.Read(bytes.NewBuffer(msgBytes), binaryOrderType, &msg)
	if err != nil {
		return
	}

	if msg.AnswersMode != kx.options.AnswersMode {
		kx.messenger.sess.debugf("[kx] msg == %+v; msgBytes == %v; b == %v", msg, msgBytes, b)
		kx.errFunc(newErrAnswersModeMismatch(kx.options.AnswersMode, msg.AnswersMode))
	}

	{
		var zeroKey [curve25519PublicKeySize]byte
		if bytes.Compare(msg.PublicKey[:], zeroKey[:]) == 0 {
			kx.errFunc(newErrInvalidPublicKey())
			return
		}
	}

	kx.messenger.sess.debugf("[kx] received msg: %+v", msg)
	kx.LockDo(func() {
		defer func() { err = wrapError(err) }()

		nextRemoteHasChanged := true
		kx.keyLocker.LockDo(func() {
			if kx.nextRemotePublicKey != nil &&
				bytes.Compare((*kx.nextRemotePublicKey)[:], msg.PublicKey[:]) == 0 {
				nextRemoteHasChanged = false
				return
			}
			kx.nextRemotePublicKey = &msg.PublicKey
		})
		if !nextRemoteHasChanged {
			//kx.errFunc(newErrRemoteKeyHasNotChanged())
			//return
		}

		err = kx.updateSecrets()
		if err != nil {
			kx.errFunc(wrapError(err))
			return
		}

		if msg.Flags.IsAnswer() || kx.options.AnswersMode != KeyExchangeAnswersModeAnswerAndWait {
			kx.remoteSessionID = &msg.SessionID
			kx.lastExchangeTS = time.Now()
			kx.sendSuccessNotifications()
		}

		if !msg.Flags.IsAnswer() && kx.options.AnswersMode != KeyExchangeAnswersModeDisable {
			// Send answer
			go func() {
				kx.mustSendPublicKey(true)
			}()
		}
	})
	return
}

func (kx *keyExchanger) sendSuccessNotifications() {
	var localNextKeyID uint64
	kx.keyLocker.RLockDo(func() {
		localNextKeyID = kx.nextLocalKeyCreatedAt
		kx.localKeyCreatedAt = localNextKeyID
	})
	func() {
		defer func() { recover() }() // just in case; TODO: remove this line
		select {
		case <-kx.ctx.Done():
		case kx.successNotifyChan <- localNextKeyID:
		default:
		}
	}()
	kx.messenger.sess.debugf("[kx] a successful key exchange, localKeyCreatedAt == %v", localNextKeyID)

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

func (kx *keyExchanger) updateKey() (result uint64) {
	var isAlreadyInProgress bool
	kx.keyLocker.RLockDo(func() {
		isAlreadyInProgress = kx.nextLocalKeyCreatedAt > kx.localKeyCreatedAt
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
	kx.keyLocker.LockDo(func() {
		kx.nextLocalPrivateKey = &privKeyCasted
		kx.nextLocalPublicKey = &pubKeyCasted
		kx.nextLocalKeyCreatedAt = uint64(time.Now().UnixNano())
		if kx.nextLocalKeyCreatedAt <= kx.localKeyCreatedAt { // could happen due to time re-synchronization
			kx.nextLocalKeyCreatedAt = kx.localKeyCreatedAt + 1
		}
		result = kx.nextLocalKeyCreatedAt
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

		// Update the key (and increase nextKeyCreatedAt)
		if time.Now().Before(kx.skipKeyUpdateUntil) {
			kx.messenger.sess.debugf("[kx] somebody already updated the key, skipping key-update iteration.")
			return
		}
		nextKeyCreatedAt := kx.updateKey()
		kx.messenger.sess.debugf("[kx] nextKeyCreatedAt == %v", nextKeyCreatedAt)
		if nextKeyCreatedAt == 0 {
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
			case newKeyCreatedAt, ok := <-kx.successNotifyChan:
				kx.messenger.sess.debugf("[kx] KeyUpdateSendWait: success (keyCreatedAt == %v)", newKeyCreatedAt)
				if !ok {
					return
				}
				if newKeyCreatedAt > nextKeyCreatedAt {
					panic(`newKeyCreatedAt > nextKeyCreatedAt`)
				}
				if newKeyCreatedAt == nextKeyCreatedAt {
					return
				}
			case <-retryTicker.C:
				kx.messenger.sess.debugf("[kx] KeyUpdateSendWait: retry (waiting for keyCreatedAt == %v)", nextKeyCreatedAt)
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

func (kx *keyExchanger) mustSendPublicKey(isAnswer bool) {
	err := kx.sendPublicKey(isAnswer)
	if err != nil {
		_ = kx.Close()
		kx.errFunc(xerrors.Errorf("[kx] unable to send a public key: %w", err))
	}
}

func (kx *keyExchanger) sendPublicKey(isAnswer bool) error {
	if kx.nextLocalPublicKey == nil && isAnswer {
		kx.updateKey()
		kx.skipKeyUpdateUntil = time.Now().Add(kx.options.KeyUpdateInterval)
	}
	kx.messenger.sess.debugf("[kx] kx.sendPublicKey(isAnswer: %v)", isAnswer)
	msg := &keySeedUpdateMessage{}
	msg.SessionID = kx.messenger.sess.id
	kx.keyLocker.RLockDo(func() {
		copy(msg.PublicKey[:], (*kx.nextLocalPublicKey)[:])
	})
	msg.Flags.SetIsAnswer(isAnswer)
	msg.AnswersMode = kx.options.AnswersMode
	return kx.send(msg)
}

func (kx *keyExchanger) send(msg *keySeedUpdateMessage) error {
	buf := bytesextra.NewWriter(make([]byte, keySeedUpdateMessageSignedSize))
	buf.CurrentPosition = keySignatureSize
	err := binary.Write(buf, binaryOrderType, msg)
	if err != nil {
		return fmt.Errorf("unable to encode keySeedUpdateMessage: %w", err)
	}
	bufBytes := buf.Storage
	kx.localIdentity.Sign(bufBytes[:keySignatureSize], bufBytes[keySignatureSize:])

	n, err := kx.messenger.Write(bufBytes)
	if err != nil {
		return fmt.Errorf("unable to send keySeedUpdateMessage: %w", err)
	}
	if n != len(bufBytes) {
		return newErrPartialWrite()
	}

	return nil
}
