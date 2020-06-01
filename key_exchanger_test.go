package secureio

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aead/ecdh"
	"github.com/stretchr/testify/assert"

	xerrors "github.com/xaionaro-go/errors"
)

func testKeyExchanger(t *testing.T, errFunc func(error)) *keyExchanger {
	ctx, cancelFunc := context.WithCancel(context.Background())
	closedChan := make(chan struct{})
	close(closedChan)
	kx := &keyExchanger{
		ctx:        ctx,
		cancelFunc: cancelFunc,
		doneFunc:   cancelFunc,
		errFunc:    errFunc,
		ecdh:       ecdh.X25519(),
		messenger: &Messenger{sess: &Session{
			ctx:                          ctx,
			backend:                      newErroneousConn(),
			state:                        newSessionStateStorage(),
			cipherKeys:                   &[][][]byte{nil}[0],
			messageHeadersPool:           newMessageHeadersPool(),
			messagesContainerHeadersPool: newMessagesContainerHeadersPool(),
			bufferPool:                   newBufferPool(1),
			packetSizeLimit:              maxPossiblePacketSize,
			establishedPayloadSize:       maxPossiblePacketSize - 100,
			waitForCipherKeyChan:         make(chan struct{}),
			options: SessionOptions{
				PayloadSizeLimit: payloadSizeLimit,
			},
			isEstablished: closedChan,
		}},
		localIdentity:  testIdentity(t),
		remoteIdentity: testIdentity(t),
	}
	sess := kx.messenger.sess
	sess.sendInfoPool = newSendInfoPool(sess)
	sess.setSecrets([][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)})
	return kx
}

func TestKeyExchanger_generateSharedKey_negative(t *testing.T) {
	errCount := 0
	kx := testKeyExchanger(t, func(err error) {
		errCount++
	})

	func() {
		defer func() {
			assert.True(t, strings.Index(fmt.Sprintf("%v", recover()), `should not happen`) != -1)
		}()
		var a [32]byte
		_, _ = kx.generateSharedKey(&a, &a)
	}()

	assert.True(t, kx.Handle(nil).(*xerrors.Error).Has(ErrTooShort{}))
	assert.True(t, kx.Handle(make([]byte, 65536)).(*xerrors.Error).Has(ErrInvalidSignature{}))
	assert.NotZero(t, kx.updateLocalKey())
	assert.NotZero(t, kx.updateLocalKey())
	kx.nextLocalKeyCreatedAt = kx.localKeyCreatedAt
	kx.cryptoRandReader = &bytes.Buffer{}
	assert.Zero(t, kx.updateLocalKey())
	assert.Equal(t, 1, errCount)
	kx.cancelFunc()
	kx.sendSuccessNotifications()
}

func TestKeyExchanger_KeyUpdateSendWait_timeout(t *testing.T) {
	errCount := 0
	kx := testKeyExchanger(t, func(err error) {
		errCount++
		assert.True(t, err.(*xerrors.Error).Has(ErrKeyExchangeTimeout{}), err)
	})
	kx.options.Timeout = time.Nanosecond
	kx.options.RetryInterval = time.Hour
	kx.KeyUpdateSendWait()
	assert.Equal(t, 1, errCount)
}
