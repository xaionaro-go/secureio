package secureio_test

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/xaionaro-go/secureio"
)

func TestIdentityMutualConfirmationOfIdentityWithPSK(t *testing.T) {
	identity0, identity1, conn0, conn1 := testPair(t)

	opts := &SessionOptions{}

	opts.KeyExchangerOptions.PSK = make([]byte, 64)
	opts.OnInitFuncs = []OnInitFunc{func(sess *Session) { readLogsOfSession(t, true, sess) }}
	opts.EnableDebug = true
	rand.Read(opts.KeyExchangerOptions.PSK)

	ctx, cancelFunc := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	defer cancelFunc()

	var wg sync.WaitGroup

	var err0 error
	var keys0 [][]byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		keys0, err0 = identity0.MutualConfirmationOfIdentity(
			ctx,
			identity1,
			conn0,
			&testLogger{t, nil},
			opts,
		)
	}()

	var err1 error
	var keys1 [][]byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		keys1, err1 = identity1.MutualConfirmationOfIdentity(
			ctx,
			identity0,
			conn1,
			&testLogger{t, nil},
			opts,
		)
	}()

	wg.Wait()

	assert.NoError(t, err0)
	assert.NoError(t, err1)
	assert.Equal(t, keys0, keys1)

	testConnIsOpen(t, conn0, conn1)
}

func TestIdentityMutualConfirmationOfIdentityWithWrongPSK(t *testing.T) {
	identity0, identity1, conn0, conn1 := testPair(t)
	defer conn0.Close()
	defer conn1.Close()

	opts0 := &SessionOptions{}
	opts1 := &SessionOptions{}

	opts0.KeyExchangerOptions.PSK = make([]byte, 64)
	opts1.KeyExchangerOptions.PSK = make([]byte, 64)
	opts0.OnInitFuncs = []OnInitFunc{func(sess *Session) { readLogsOfSession(t, false, sess) }}
	opts1.OnInitFuncs = []OnInitFunc{func(sess *Session) { readLogsOfSession(t, false, sess) }}
	opts0.EnableDebug = true
	opts1.EnableDebug = true
	rand.Read(opts0.KeyExchangerOptions.PSK)
	copy(opts1.KeyExchangerOptions.PSK, opts0.KeyExchangerOptions.PSK)
	opts0.KeyExchangerOptions.PSK[63] = 0
	opts1.KeyExchangerOptions.PSK[63] = 1

	ctx := context.Background()

	var wg sync.WaitGroup

	var err0 error
	var keys0 [][]byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer fmt.Println("identity0.MutualConfirmationOfIdentity() finished")
		keys0, err0 = identity0.MutualConfirmationOfIdentity(
			ctx,
			identity1,
			conn0,
			//&dummyEventHandler{},
			&testLogger{t, nil},
			opts0,
		)
	}()

	var err1 error
	var keys1 [][]byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer fmt.Println("identity1.MutualConfirmationOfIdentity() finished")
		keys1, err1 = identity1.MutualConfirmationOfIdentity(
			ctx,
			identity0,
			conn1,
			//&dummyEventHandler{},
			&testLogger{t, nil},
			opts1,
		)
	}()

	wg.Wait()

	assert.Error(t, err0)
	assert.Error(t, err1)
	assert.Nil(t, keys0)
	assert.Nil(t, keys1)

	testConnIsOpen(t, conn0, conn1)
}
