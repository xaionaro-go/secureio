package secureio

import (
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIdentityMutualConfirmationOfIdentityWithPSK(t *testing.T) {
	identity0, identity1, conn0, conn1 := testPair(t)

	opts := &SessionOptions{}

	opts.KeyExchangerOptions.PSK = make([]byte, 64)
	rand.Read(opts.KeyExchangerOptions.PSK)

	ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))

	var wg sync.WaitGroup

	var err0 error
	var key0 []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		err0, key0 = identity0.MutualConfirmationOfIdentity(
			ctx,
			identity1,
			conn0,
			&testLogger{"0", t, true, nil},
			opts,
		)
	}()

	var err1 error
	var key1 []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		err1, key1 = identity1.MutualConfirmationOfIdentity(
			ctx,
			identity0,
			conn1,
			&testLogger{"1", t, true, nil},
			opts,
		)
	}()

	wg.Wait()

	assert.NoError(t, err0)
	assert.NoError(t, err1)
	assert.Equal(t, key0, key1)
}

func TestIdentityMutualConfirmationOfIdentityWithWrongPSK(t *testing.T) {
	identity0, identity1, conn0, conn1 := testPair(t)

	opts0 := &SessionOptions{}
	opts1 := &SessionOptions{}

	opts0.KeyExchangerOptions.PSK = make([]byte, 64)
	opts1.KeyExchangerOptions.PSK = make([]byte, 64)
	rand.Read(opts0.KeyExchangerOptions.PSK)
	copy(opts1.KeyExchangerOptions.PSK, opts0.KeyExchangerOptions.PSK)
	opts0.KeyExchangerOptions.PSK[63] = 0
	opts1.KeyExchangerOptions.PSK[63] = 1

	ctx := context.Background()

	var wg sync.WaitGroup

	var err0 error
	var key0 []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		err0, key0 = identity0.MutualConfirmationOfIdentity(
			ctx,
			identity1,
			conn0,
			&testLogger{"0", t, false, nil},
			opts0,
		)
	}()

	var err1 error
	var key1 []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		err1, key1 = identity1.MutualConfirmationOfIdentity(
			ctx,
			identity0,
			conn1,
			&testLogger{"1", t, false, nil},
			opts1,
		)
	}()

	wg.Wait()

	assert.Error(t, err0)
	assert.Error(t, err1)
	assert.Nil(t, key0)
	assert.Nil(t, key1)
}
