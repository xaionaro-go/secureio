package secureio

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand"
	"sync"
	"time"

	"github.com/wsddn/go-ecdh"
	"github.com/xaionaro-go/errors"
	"golang.org/x/crypto/ed25519"
)

const (
	PublicKeySize    = ed25519.PublicKeySize
	PrivateKeySize   = ed25519.PublicKeySize
	KeySignatureSize = ed25519.SignatureSize
)

var (
	binaryOrderType = binary.LittleEndian
)

var (
	ErrWrongKeySeedLength = errors.New("wrong length of the key seed")
	ErrKeyExchangeTimeout = errors.New("key exchange timeout")
)

type keyExchanger struct {
	locker                     sync.Mutex
	okFunc                     func([]byte)
	errFunc                    func(error)
	stopChan                   chan struct{}
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

func newKeyExchanger(localIdentity *Identity, remoteIdentity *Identity, messenger *Messenger, okFunc func([]byte), errFunc func(error)) *keyExchanger {
	kx := &keyExchanger{
		okFunc:         okFunc,
		errFunc:        errFunc,
		stopChan:       make(chan struct{}),
		localIdentity:  localIdentity,
		remoteIdentity: remoteIdentity,
		messenger:      messenger,
		ecdh:           ecdh.NewCurve25519ECDH(),
	}
	messenger.SetHandler(kx)
	kx.start()
	return kx
}

func (kx *keyExchanger) LockDo(fn func()) {
	kx.locker.Lock()
	defer kx.locker.Unlock()
	fn()
}

func (kx *keyExchanger) generateSharedKey(localPrivateKey *[PrivateKeySize]byte, remotePublicKey *[PublicKeySize]byte) ([]byte, error) {
	return kx.ecdh.GenerateSharedSecret(localPrivateKey, remotePublicKey)
}

func (kx *keyExchanger) Handle(b []byte) (err error) {
	kx.LockDo(func() {
		msg := &kx.remoteKeySeedUpdateMessage
		err = binary.Read(bytes.NewBuffer(b), binaryOrderType, msg)
		if err != nil {
			return
		}
		if err = kx.remoteIdentity.VerifySignature(msg.Signature[:], msg.PublicKey[:]); err != nil {
			kx.messenger.sess.logger.Debugf("wrong signature: %v", err)
			return
		}
		nextLocal := kx.nextLocalPrivateKey
		if nextLocal == nil {
			return // Not ready, yet. It's required to call UpdateKey(), first
		}
		nextRemote := &msg.PublicKey
		nextKey, genErr := kx.generateSharedKey(nextLocal, nextRemote)
		if genErr != nil {
			kx.errFunc(errors.Wrap(genErr))
			_ = kx.Close()
			return
		}
		kx.okFunc(nextKey)
		kx.lastExchangeTS = time.Now()

		if mathrand.Intn(4) == 0 { // every 4th time resend our data (it seems the remote side didn't receive it if it sends the message 4 times)
			err := kx.sendPublicKey()
			if err != nil {
				_ = kx.Close()
				kx.errFunc(errors.Wrap(err))
				return
			}
		}
	})
	return
}

func (kx *keyExchanger) Close() error {
	kx.stop()
	kx.messenger.sess.logger.Debugf("key exchanger closed")
	return nil
}

func (kx *keyExchanger) stop() {
	kx.stopChan <- struct{}{}
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
	if now.Sub(lastExchangeTS) < time.Minute {
		return
	}
	if !lastExchangeTS.IsZero() && now.Sub(lastExchangeTS) > 2*time.Minute {
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
	for {
		select {
		case <-kx.stopChan:
			_ = kx.messenger.Close()
			close(kx.stopChan)
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
