// +build linux

package secureio_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/xaionaro-go/secureio"
)

func TestMissedKeySeedMessage(t *testing.T) {
	conn0, conn1 := testUDPPair(t)
	identity0, identity1, _c0, _c1 := testPair(t)
	_c0.Close()
	_c1.Close()

	opts := &SessionOptions{}
	opts.OnInitFuncs = []OnInitFunc{func(sess *Session) { printLogsOfSession(t, false, sess) }}
	opts.EnableDebug = true
	opts.EnableInfo = true
	opts.PacketIDStorageSize = -1                             // it's UDP :(
	opts.KeyExchangerOptions.RetryInterval = time.Millisecond // speed-up the unit test

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		keys, err := identity0.MutualConfirmationOfIdentity(ctx, identity1, conn0, &testLogger{t, nil}, opts)
		assert.NoError(t, err)
		if assert.Equal(t, 4, len(keys)) {
			assert.Equal(t, 32, len(keys[0]))
		}
	}()

	// Getting one packet missed
	readBuf := make([]byte, 65536)
	_, err := conn1.Read(readBuf)
	assert.NoError(t, err)

	wg.Add(1)
	go func() {
		defer wg.Done()
		keys, err := identity1.MutualConfirmationOfIdentity(ctx, identity0, conn1, &testLogger{t, nil}, opts)
		assert.NoError(t, err)
		if assert.Equal(t, 4, len(keys)) {
			assert.Equal(t, 32, len(keys[0]))
		}
	}()

	wg.Wait()
}
