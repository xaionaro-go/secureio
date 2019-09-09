package secureio

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand"
	"sync"
	"time"

	"github.com/wsddn/go-ecdh"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"

	"github.com/xaionaro-go/errors"
)

const (
	DefaultKeyExchangeInterval = time.Minute
	DefaultKeyExchangeTimeout  = time.Minute
)

const (
	PublicKeySize    = ed25519.PublicKeySize
	PrivateKeySize   = ed25519.PublicKeySize
	KeySignatureSize = ed25519.SignatureSize
)

var (
	binaryOrderType = binary.LittleEndian

	// Salt is used to append PSKs. If you change this value then
	// it is required to change it on both sides.
	Salt = []byte(`xaionaro-go/secureio.KeyExchanger`)
)

var (
	ErrWrongKeySeedLength = errors.New("wrong length of the key seed")
	ErrKeyExchangeTimeout = errors.New("key exchange timeout")
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
	nextLocalPrivateKey        *[PrivateKeySize]byte
	nextLocalPublicKey         *[PublicKeySize]byte
	remoteKeySeedUpdateMessage keySeedUpdateMessage
	localKeySeedUpdateMessage  keySeedUpdateMessage
	localIdentity              *Identity
	remoteIdentity             *Identity
	messenger                  *Messenger
	ecdh                       ecdh.ECDH
}

type KeyExchangerOptions struct {
	Interval time.Duration
	Timeout  time.Duration
	PSK      []byte
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
		ecdh:           ecdh.NewCurve25519ECDH(),
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
	localPrivateKey *[PrivateKeySize]byte,
	remotePublicKey *[PublicKeySize]byte,
) ([]byte, error) {
	key, err := kx.ecdh.GenerateSharedSecret(localPrivateKey, remotePublicKey)
	if err != nil {
		return nil, err
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

	return key, err
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
	defer func() { err = errors.Wrap(err) }()

	kx.LockDo(func() {
		msg := &kx.remoteKeySeedUpdateMessage
		err = binary.Read(bytes.NewBuffer(b), binaryOrderType, msg)
		if err != nil {
			return
		}
		if err = kx.remoteIdentity.VerifySignature(msg.Signature[:], msg.PublicKey[:]); err != nil {
			if kx.messenger.sess.eventHandler.IsDebugEnabled() {
				kx.messenger.sess.eventHandler.Debugf("wrong signature: %v", err)
			}
			return
		}
		nextLocal := kx.nextLocalPrivateKey
		if nextLocal == nil {
			return // Not ready, yet. It's required to call UpdateKey(), first
		}
		nextRemote := &msg.PublicKey
		nextKey, genErr := kx.generateSharedKey(nextLocal, nextRemote)
		if genErr != nil {
			_ = kx.Close()
			if genErr.(*errors.Error).Err != ErrAlreadyClosed || !kx.isDone() {
				kx.errFunc(errors.Wrap(genErr))
			}
			return
		}
		kx.okFunc(nextKey)
		kx.lastExchangeTS = time.Now()

		if mathrand.Intn(2) == 0 { // every 2th time resend our data (it seems the remote side didn't receive it if keeps sending us this messages)
			err := kx.sendPublicKey()
			if err != nil {
				_ = kx.Close()
				if err.(*errors.Error).Err != ErrAlreadyClosed || !kx.isDone() {
					kx.errFunc(errors.Wrap(err))
				}
				return
			}
		}
	})
	return
}

func (kx *keyExchanger) Close() error {
	kx.stop()
	if kx.messenger.sess.eventHandler.IsDebugEnabled() {
		kx.messenger.sess.eventHandler.Debugf("key exchanger closed")
	}
	return nil
}

func (kx *keyExchanger) stop() {
	kx.cancelFunc()
}

func (kx *keyExchanger) start() {
	go kx.loop()
}

func (kx *keyExchanger) iterate() {
	var lastExchangeTS time.Time
	kx.LockDo(func() {
		lastExchangeTS = kx.lastExchangeTS
	})
	now := time.Now()
	if now.Sub(lastExchangeTS) < kx.options.Interval {
		return
	}
	if !lastExchangeTS.IsZero() && now.Sub(lastExchangeTS) >
		kx.options.Interval+kx.options.Timeout {
		_ = kx.Close()
		kx.errFunc(errors.Wrap(ErrKeyExchangeTimeout))
		return
	}
	err := kx.sendPublicKey()
	if err != nil {
		_ = kx.Close()
		kx.errFunc(errors.Wrap(err))
		return
	}
}

func (kx *keyExchanger) loop() {
	kx.UpdateKey()
	kx.iterate()
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
	msg := &kx.localKeySeedUpdateMessage
	copy(msg.PublicKey[:], (*kx.nextLocalPublicKey)[:])
	kx.localIdentity.Sign(msg.Signature[:], msg.PublicKey[:])
	return kx.send(msg)
}

func (kx *keyExchanger) UpdateKey() {
	privKey, pubKey, err := kx.ecdh.GenerateKey(rand.Reader)
	if err != nil {
		_ = kx.Close()
		kx.errFunc(errors.Wrap(err))
		return
	}
	kx.nextLocalPrivateKey = privKey.(*[PrivateKeySize]byte)
	kx.nextLocalPublicKey = pubKey.(*[PublicKeySize]byte)
	return
}

func (kx *keyExchanger) send(msg *keySeedUpdateMessage) error {
	return binary.Write(kx.messenger, binaryOrderType, msg)
}
