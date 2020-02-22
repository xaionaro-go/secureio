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
	identity0, identity1, _, _ := testPair(t)

	opts := &SessionOptions{}
	opts.OnInitFuncs = []OnInitFunc{func(sess *Session) { readLogsOfSession(t, false, sess) }}
	opts.EnableDebug = true
	opts.EnableInfo = true
	opts.AllowReorderingAndDuplication = true                 // it's UDP :(
	opts.KeyExchangerOptions.RetryInterval = time.Millisecond // speed-up the unit test

	ctx := context.Background()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		key, err := identity0.MutualConfirmationOfIdentity(ctx, identity1, conn0, &testLogger{t, nil}, opts)
		assert.Equal(t, 32, len(key))
		assert.NoError(t, err)
	}()

	// Getting one packet missed
	missedBytes := 0
	for {
		readBuf := make([]byte, 65536)
		n, err := conn1.Read(readBuf)
		assert.NoError(t, err)
		missedBytes += n
		if missedBytes >= 32+32+1 {
			break
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		key, err := identity1.MutualConfirmationOfIdentity(ctx, identity0, conn1, &testLogger{t, nil}, opts)
		assert.Equal(t, 32, len(key))
		assert.NoError(t, err)
	}()

	wg.Wait()
}
