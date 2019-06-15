package cryptofilter

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/wsddn/go-ecdh"
	"github.com/xaionaro-go/errors"
	"golang.org/x/crypto/ed25519"
)

const (
	PublicKeySize    = ed25519.PublicKeySize
	PrivateKeySize   = ed25519.PrivateKeySize
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
	nextLocalPrivateKey        []byte
	nextLocalPublicKey         []byte
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

func (kx *keyExchanger) generateSharedKey(localPrivateKey, remotePublicKey []byte) ([]byte, error) {
	return kx.ecdh.GenerateSharedSecret(localPrivateKey, remotePublicKey)
}

func (kx *keyExchanger) ReadFrom(r io.Reader) (n int64, err error) {
	kx.LockDo(func() {
		msg := &kx.remoteKeySeedUpdateMessage
		err = binary.Read(r, binaryOrderType, msg)
		if err != nil {
			return
		}
		if kx.remoteIdentity.VerifySignature(msg.Signature[:], msg.PublicKey[:]) != nil {
			return
		}
		nextKey, genErr := kx.generateSharedKey(kx.nextLocalPrivateKey, msg.PublicKey[:])
		if genErr != nil {
			kx.errFunc(errors.Wrap(genErr))
			_ = kx.Close()
			return
		}
		kx.okFunc(nextKey)
		kx.lastExchangeTS = time.Now()
	})
	if err == nil {
		n = keySeedUpdateMessageSize
	} else {
		_ = kx.Close()
		kx.errFunc(errors.Wrap(err))
	}
	return
}

func (kx *keyExchanger) Close() error {
	kx.stop()
	return nil
}

func (kx *keyExchanger) stop() {
	kx.stopChan <- struct{}{}
}

func (kx *keyExchanger) start() {
	go kx.loop()
}

func (kx *keyExchanger) loop() {
	sendPublicKeyTicker := time.NewTicker(time.Second)
	for {
		select {
		case <-kx.stopChan:
			_ = kx.messenger.Close()
			close(kx.stopChan)
			return
		case <-sendPublicKeyTicker.C:
			var lastExchangeTS time.Time
			kx.LockDo(func() {
				lastExchangeTS = kx.lastExchangeTS
			})
			now := time.Now()
			if now.Sub(lastExchangeTS) < time.Minute {
				continue
			}
			if now.Sub(lastExchangeTS) > 2*time.Minute {
				_ = kx.Close()
				kx.errFunc(errors.Wrap(ErrKeyExchangeTimeout))
				continue
			}
			err := kx.sendPublicKey()
			if err != nil {
				_ = kx.Close()
				kx.errFunc(errors.Wrap(err))
				continue
			}
		}
	}
}

func (kx *keyExchanger) sendPublicKey() error {
	msg := &kx.localKeySeedUpdateMessage
	copy(msg.PublicKey[:], kx.nextLocalPublicKey)
	sign := ed25519.Sign(kx.localIdentity.Keys.Private, msg.PublicKey[:])
	copy(msg.Signature[:], sign)
	return kx.send(msg)
}

func (kx *keyExchanger) UpdateKey() {
	privKey, pubKey, err := kx.ecdh.GenerateKey(rand.Reader)
	if err != nil {
		_ = kx.Close()
		kx.errFunc(errors.Wrap(err))
		return
	}
	kx.nextLocalPrivateKey = privKey.([]byte)
	kx.nextLocalPublicKey = pubKey.([]byte)
	return
}

func (kx *keyExchanger) send(msg *keySeedUpdateMessage) error {
	return binary.Write(kx.messenger, binaryOrderType, msg)
}
