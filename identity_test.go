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

	psk := make([]byte, 64)
	rand.Read(psk)

	ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(time.Second))

	var wg sync.WaitGroup

	var err0 error
	var key0 []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		err0, key0 = identity0.MutualConfirmationOfIdentityWithPSK(
			ctx,
			identity1,
			conn0,
			&testLogger{"0", t, true},
			psk,
		)
	}()

	var err1 error
	var key1 []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		err1, key1 = identity1.MutualConfirmationOfIdentityWithPSK(
			ctx,
			identity0,
			conn1,
			&testLogger{"1", t, true},
			psk,
		)
	}()

	wg.Wait()

	assert.NoError(t, err0)
	assert.NoError(t, err1)
	assert.Equal(t, key0, key1)
}

func TestIdentityMutualConfirmationOfIdentityWithWrongPSK(t *testing.T) {
	identity0, identity1, conn0, conn1 := testPair(t)

	psk0 := make([]byte, 64)
	psk1 := make([]byte, 64)
	rand.Read(psk0)
	copy(psk1, psk0)
	psk0[63] = 0
	psk1[63] = 1

	ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(time.Millisecond))

	var wg sync.WaitGroup

	var err0 error
	var key0 []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		err0, key0 = identity0.MutualConfirmationOfIdentityWithPSK(
			ctx,
			identity1,
			conn0,
			&testLogger{"0", t, false},
			psk0,
		)
	}()

	var err1 error
	var key1 []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		err1, key1 = identity1.MutualConfirmationOfIdentityWithPSK(
			ctx,
			identity0,
			conn1,
			&testLogger{"1", t, false},
			psk1,
		)
	}()

	wg.Wait()

	assert.Error(t, err0)
	assert.Error(t, err1)
	assert.Nil(t, key0)
	assert.Nil(t, key1)
}
