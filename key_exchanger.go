package secureio

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"

	"github.com/aead/ecdh"
	"github.com/xaionaro-go/bytesextra"

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

func (secretID secretID) String() string {
	switch secretID {
	case secretIDRecentBoth:
		return "recent_both"
	case secretIDRecentLocal:
		return "recent_local"
	case secretIDRecentRemote:
		return "recent_remote"
	case secretIDPrevious:
		return "previous"
	}
	return fmt.Sprintf("%d", secretID)
}

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
	keyUpdateLocker       lockerMutex
	skipKeyUpdateUntil    time.Time

	cryptoRandReader io.Reader
	wg               sync.WaitGroup
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
		successNotifyChan: make(chan uint64, 1),
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

func (kx *keyExchanger) getCryptoRandReader() io.Reader {
	if kx.cryptoRandReader == nil {
		return rand.Reader
	}
	return kx.cryptoRandReader
}

func (kx *keyExchanger) LockDo(fn func()) {
	kx.locker.Lock()
	defer kx.locker.Unlock()
	fn()
}

func (kx *keyExchanger) generateSharedKeyBySecretID(
	secretID secretID,
) (sharedKey []byte, err *xerrors.Error) {
	defer func() {
		if err != nil {
			err.SetFormat(xerrors.FormatOneLine)
		}
		if kx.messenger != nil {
			kx.messenger.sess.debugf("[kx] generateSharedKeyBySecretID(%v) -> %v, %v",
				secretID, sharedKey, err)
		}
	}()

	var localPrivateKey *[curve25519PrivateKeySize]byte
	var remotePublicKey *[curve25519PublicKeySize]byte
	kx.keyLocker.RLockDo(func() {
		switch secretID {
		case secretIDRecentBoth:
			localPrivateKey = kx.nextLocalPrivateKey
			remotePublicKey = kx.nextRemotePublicKey
		case secretIDRecentLocal:
			localPrivateKey = kx.nextLocalPrivateKey
			remotePublicKey = kx.prevRemotePublicKey
		case secretIDRecentRemote:
			localPrivateKey = kx.prevLocalPrivateKey
			remotePublicKey = kx.nextRemotePublicKey
		case secretIDPrevious:
			localPrivateKey = kx.prevLocalPrivateKey
			remotePublicKey = kx.prevRemotePublicKey
		}
	})

	return kx.generateSharedKey(localPrivateKey, remotePublicKey)
}

func (kx *keyExchanger) generateSharedKey(
	localPrivateKey *[curve25519PrivateKeySize]byte,
	remotePublicKey *[curve25519PublicKeySize]byte,
) (sharedKey []byte, err *xerrors.Error) {
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
	if psk != nil {
		pskXORer := hash(psk, Salt, []byte("cipherKey"))
		for i := 0; i < len(pskXORer); i++ {
			key[i] ^= pskXORer[i]
		}
	}

	return key, nil
}

func (kx *keyExchanger) updateSecrets() (err error) {
	defer func() { err = wrapError(err) }()

	newSecrets := make([][]byte, secretIDs)
	for secretIdx := 0; secretIdx < secretIDs; secretIdx++ {
		newSecret, genErr := kx.generateSharedKeyBySecretID(secretID(secretIdx))
		if genErr != nil &&
			!genErr.Has(errLocalPrivateKeyIsNil{}) &&
			!genErr.Has(errRemotePublicKeyIsNil{}) {
			return genErr
		}
		newSecrets[secretIdx] = newSecret
	}

	if len(newSecrets[secretIDRecentBoth]) != 0 {
		kx.messenger.sess.debugf("[kx] set the secrets == %v", newSecrets)
		kx.setSecretsFunc(newSecrets)
	}
	return nil
}

func (kx *keyExchanger) parseAndCheck(msg *keySeedUpdateMessage, b []byte) (err error) {
	if len(b) < keySeedUpdateMessageSignedSize {
		return newErrTooShort(uint(keySeedUpdateMessageSignedSize), uint(len(b)))
	}

	signature := b[:keySignatureSize]
	msgBytes := b[keySignatureSize:keySeedUpdateMessageSignedSize]
	if len(b) > keySeedUpdateMessageSignedSize {
		kx.messenger.sess.debugf("[kx] ignored the tail of length %v", keySeedUpdateMessageSignedSize-len(b))
	}
	if kx.remoteIdentity != nil {
		if err = kx.remoteIdentity.VerifySignature(signature, msgBytes); err != nil {
			kx.messenger.sess.debugf("[kx] ignoring the message from %+v due to the wrong signature: %v", kx.remoteIdentity, err)
			return
		}
	}

	err = binary.Read(bytes.NewBuffer(msgBytes), binaryOrderType, msg)
	if err != nil {
		return wrapError(err)
	}

	if msg.AnswersMode != kx.options.AnswersMode {
		kx.messenger.sess.debugf("[kx] msg == %+v; msgBytes == %v; b == %v", msg, msgBytes, b)
		err = newErrAnswersModeMismatch(kx.options.AnswersMode, msg.AnswersMode)
		kx.errFunc(err)
		return
	}

	var zeroKey [curve25519PublicKeySize]byte
	if bytes.Compare(msg.KXPublicKey[:], zeroKey[:]) == 0 {
		err = newErrInvalidPublicKey()
		kx.errFunc(err)
		return
	}

	return nil
}

func (kx *keyExchanger) setRemoteIdentityFromPublicKey(origMsg, remotePubKey []byte) (isOK bool) {
	kx.messenger.sess.debugf("[kx] setting the remote identity to %+v", remotePubKey[:])

	// Parse the remote key
	remoteIdentity, err := NewRemoteIdentityFromPublicKey(remotePubKey[:])
	if err != nil {
		kx.errFunc(wrapError(err))
		return false
	}

	// The signature wasn't verified on the stage of kx.parseAndCheck, so we need to verify it at least now
	if len(origMsg) < keySeedUpdateMessageSignedSize {
		kx.errFunc(xerrors.Errorf("[kx] too short message: %d < %d", len(origMsg), keySeedUpdateMessageSignedSize))
		return false
	}
	if err = remoteIdentity.VerifySignature(origMsg[:keySignatureSize], origMsg[keySignatureSize:keySeedUpdateMessageSignedSize]); err != nil {
		kx.messenger.sess.debugf("[kx] ignoring the message from %+v due to the wrong signature: %v", remoteIdentity, err)
		return false
	}

	// Everything is OK, let's remember the new value
	kx.remoteIdentity = remoteIdentity
	kx.messenger.sess.lockDo(func() {
		kx.messenger.sess.remoteIdentity = kx.remoteIdentity
	})
	return true
}

func (kx *keyExchanger) setRemoteSessionID(sessID *SessionID) {
	kx.messenger.sess.debugf("[kx] setting the remote session ID to %+v", sessID)
	kx.remoteSessionID = sessID
	kx.messenger.sess.setRemoteSessionID(kx.remoteSessionID)
}

func (kx *keyExchanger) setNextRemotePublicKey(kxPublicKey *[32]byte) {
	nextRemoteHasChanged := true
	kx.keyLocker.LockDo(func() {
		if kx.nextRemotePublicKey != nil &&
			bytes.Compare((*kx.nextRemotePublicKey)[:], kxPublicKey[:]) == 0 {
			nextRemoteHasChanged = false
			return
		}
		kx.prevRemotePublicKey = kx.nextRemotePublicKey
		kx.nextRemotePublicKey = kxPublicKey
	})
	if !nextRemoteHasChanged {
		//kx.errFunc(newErrRemoteKeyHasNotChanged())
		//return
	}
}

func (kx *keyExchanger) Handle(b []byte) (err error) {
	defer func() { err = wrapError(err) }()

	var msg keySeedUpdateMessage
	if err = kx.parseAndCheck(&msg, b); err != nil {
		return
	}
	kx.messenger.sess.debugf("[kx] received msg: %+v", msg)

	kx.LockDo(func() {
		defer func() { err = wrapError(err) }()

		kx.messenger.sess.debugf("[kx] received msg: locked")
		defer kx.messenger.sess.debugf("[kx] received msg: unlocked")

		select {
		case <-kx.ctx.Done():
			err = newErrAlreadyClosed()
			return
		default:
		}

		if kx.remoteIdentity == nil {
			if !kx.setRemoteIdentityFromPublicKey(b, msg.IdentityPublicKey[:]) {
				return
			}
		}

		if kx.remoteSessionID == nil {
			kx.setRemoteSessionID(&msg.SessionID)
		}

		kx.setNextRemotePublicKey(&msg.KXPublicKey)

		err = kx.updateSecrets()
		if err != nil {
			kx.errFunc(wrapError(err))
			return
		}

		if msg.Flags.IsAnswer() || kx.options.AnswersMode != KeyExchangeAnswersModeAnswerAndWait {
			kx.lastExchangeTS = timeNow()
			kx.sendSuccessNotifications()
		}

		if !msg.Flags.IsAnswer() && kx.options.AnswersMode != KeyExchangeAnswersModeDisable {
			// Send answer
			kx.wg.Add(1)
			go func() {
				defer kx.wg.Done()
				kx.mustSendPublicKey(true)
			}()
		}
	})
	return
}

func (kx *keyExchanger) sendSuccessNotifications() {
	kx.messenger.sess.debugf("[kx] sendSuccessNotifications()")
	var localNextKeyID uint64
	kx.keyLocker.RLockDo(func() {
		localNextKeyID = kx.nextLocalKeyCreatedAt
		kx.localKeyCreatedAt = localNextKeyID
	})
	func() {
		defer func() {
			// just in case; TODO: remove this `defer`
			err := recover()
			if err != nil {
				kx.errFunc(fmt.Errorf("panic: %s", err))
			}
		}()
		select {
		case <-kx.ctx.Done():
			kx.messenger.sess.debugf("[kx] cancelled: kx.successNotifyChan <- localNextKeyID<%v>", localNextKeyID)
		case kx.successNotifyChan <- localNextKeyID:
			kx.messenger.sess.debugf("[kx] sent kx.successNotifyChan <- localNextKeyID<%v>", localNextKeyID)
		default:
			kx.messenger.sess.debugf("[kx] cannot send: kx.successNotifyChan <- localNextKeyID<%v>", localNextKeyID)
		}
	}()
	kx.messenger.sess.debugf("[kx] a successful key exchange, localKeyCreatedAt == %v", localNextKeyID)

	kx.doneFunc()
}

func (kx *keyExchanger) Close() error {
	kx.messenger.sess.debugf("[kx] key exchanger Close()")
	kx.stop()
	return nil
}

func (kx *keyExchanger) stop() {
	kx.cancelFunc()
}

func (kx *keyExchanger) start() {
	kx.messenger.sess.debugf("[kx] kx.Start()")
	kx.wg.Add(1)
	go func() {
		defer kx.wg.Done()
		kx.loop()
	}()
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

func (kx *keyExchanger) updateLocalKey() (result uint64) {
	var isAlreadyInProgress bool
	var nextLocalKeyCreatedAt uint64
	kx.keyLocker.RLockDo(func() {
		isAlreadyInProgress = kx.nextLocalKeyCreatedAt > kx.localKeyCreatedAt
		nextLocalKeyCreatedAt = kx.nextLocalKeyCreatedAt
	})
	if isAlreadyInProgress {
		kx.messenger.sess.debugf("[kx] is already in progress: %v", nextLocalKeyCreatedAt)
		return nextLocalKeyCreatedAt
	}

	privKey, pubKey, err := kx.ecdh.GenerateKey(kx.getCryptoRandReader())
	if err != nil {
		_ = kx.Close()
		kx.errFunc(xerrors.Errorf("[kx] unable to generate ECDH keys: %w", err))
		return 0
	}
	privKeyCasted := privKey.([curve25519PrivateKeySize]byte)
	pubKeyCasted := pubKey.([curve25519PublicKeySize]byte)
	kx.keyLocker.LockDo(func() {
		kx.prevLocalPrivateKey = kx.nextLocalPrivateKey
		kx.nextLocalPrivateKey = &privKeyCasted
		kx.nextLocalPublicKey = &pubKeyCasted
		kx.nextLocalKeyCreatedAt = uint64(timeNow().UnixNano())
		if kx.nextLocalKeyCreatedAt <= kx.localKeyCreatedAt { // could happen due to time re-synchronization
			kx.nextLocalKeyCreatedAt = kx.localKeyCreatedAt + 1
		}
		result = kx.nextLocalKeyCreatedAt
	})

	err = kx.updateSecrets()
	if err != nil {
		kx.errFunc(wrapError(err))
		return
	}

	return
}

func (kx *keyExchanger) makeSuccessNotifyChanEmpty() (isDone bool) {
	for {
		select {
		case <-kx.ctx.Done():
			return true
		case _, ok := <-kx.successNotifyChan:
			if !ok {
				return true
			}
			continue
		default:
		}
		return false
	}
}

func (kx *keyExchanger) getNextKeyCreatedAt() (nextKeyCreatedAt uint64) {
	kx.LockDo(func() {
		nextKeyCreatedAt = kx.updateLocalKey()
	})
	kx.messenger.sess.debugf("[kx] nextKeyCreatedAt == %v", nextKeyCreatedAt)
	return
}

func (kx *keyExchanger) KeyUpdateSendWait() {
	kx.messenger.sess.debugf("[kx] KeyUpdateSendWait")
	kx.keyUpdateLocker.LockDo(func() {
		// Check if we may update the key right now
		if timeNow().Before(kx.skipKeyUpdateUntil) {
			kx.messenger.sess.debugf("[kx] somebody already updated the key, skipping key-update iteration.")
			return
		}

		// Empty the chan (to wait for the our event only on retries)
		if kx.makeSuccessNotifyChanEmpty() {
			return
		}

		// Update the key (and increase nextKeyCreatedAt)
		nextKeyCreatedAt := kx.getNextKeyCreatedAt()
		if nextKeyCreatedAt == 0 {
			return
		}

		// Send
		kx.mustSendPublicKey(false)

		// Send retries:
		kx.retryUntilSuccessOrTimeout(nextKeyCreatedAt)
	})
}

func (kx *keyExchanger) retryUntilSuccessOrTimeout(nextKeyCreatedAt uint64) {
	checkNewKeyCreatedAt := func(newKeyCreatedAt uint64) bool {
		kx.messenger.sess.debugf("[kx] checkNewKeyCreatedAt: %v ?= %v", newKeyCreatedAt, nextKeyCreatedAt)
		return newKeyCreatedAt >= nextKeyCreatedAt
	}
	checkSuccessNotifyChan := func() bool {
		select {
		case newKeyCreatedAt, ok := <-kx.successNotifyChan:
			kx.messenger.sess.debugf("[kx] retryUntilSuccessOrTimeout: late-success (keyCreatedAt == %v)", newKeyCreatedAt)
			if !ok {
				return true
			}
			return checkNewKeyCreatedAt(newKeyCreatedAt)
		default:
			return false
		}
	}
	timeoutTimer := time.NewTimer(kx.options.Timeout)
	retryTicker := time.NewTicker(kx.options.RetryInterval)
	defer retryTicker.Stop()
	for {
		select {
		case <-kx.ctx.Done():
			kx.messenger.sess.debugf("[kx] retryUntilSuccessOrTimeout: done")
			return
		case newKeyCreatedAt, ok := <-kx.successNotifyChan:
			kx.messenger.sess.debugf("[kx] retryUntilSuccessOrTimeout: success (keyCreatedAt == %v)", newKeyCreatedAt)
			if !ok {
				return
			}
			if checkNewKeyCreatedAt(newKeyCreatedAt) {
				return
			}
		case <-retryTicker.C:
			kx.messenger.sess.debugf("[kx] retryUntilSuccessOrTimeout: retry (waiting for keyCreatedAt == %v)", nextKeyCreatedAt)
			if checkSuccessNotifyChan() { // just in case; TODO: check if it is really useful
				return
			}
			runtime.Gosched()
			kx.mustSendPublicKey(false)
		case <-timeoutTimer.C:
			kx.messenger.sess.debugf("[kx] retryUntilSuccessOrTimeout: timeout")
			if checkSuccessNotifyChan() { // just in case; TODO: check if it is really useful
				return
			}
			_ = kx.Close()
			kx.errFunc(newErrKeyExchangeTimeout())
			return
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
	if kx.nextLocalPublicKey == nil && isAnswer {
		kx.updateLocalKey()
		kx.skipKeyUpdateUntil = timeNow().Add(kx.options.KeyUpdateInterval)
	}
	kx.messenger.sess.debugf("[kx] kx.sendPublicKey(isAnswer: %v)", isAnswer)
	msg := &keySeedUpdateMessage{}
	copy(msg.IdentityPublicKey[:], kx.localIdentity.Keys.Public)
	msg.SessionID = kx.messenger.sess.id
	kx.keyLocker.RLockDo(func() {
		copy(msg.KXPublicKey[:], (*kx.nextLocalPublicKey)[:])
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

// WaitForClosure waits until the keyExchanger will be closed and will finish
// everything.
func (kx *keyExchanger) WaitForClosure() {
	kx.wg.Wait()
}
