package secureio

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendInfo_SendID(t *testing.T) {
	assert.Equal(t, uint64(1), (&SendInfo{sendID: 1}).SendID())
}

func TestSendInfoPool_positive(t *testing.T) {
	pool := newSendInfoPool()
	sendInfo := pool.AcquireSendInfo(context.Background())
	close(sendInfo.c)
	sendInfo.Release()
}

func TestSendInfoPool_releaseNonClosed(t *testing.T) {
	defer func() {
		err := recover()
		assert.NotNil(t, err)
	}()

	pool := newSendInfoPool()
	sendInfo := pool.AcquireSendInfo(context.Background())
	sendInfo.Release()
}

func TestSendInfoPool_releaseNonBusy(t *testing.T) {
	defer func() {
		err := recover()
		assert.NotNil(t, err)
	}()

	pool := newSendInfoPool()
	sendInfo := pool.AcquireSendInfo(context.Background())
	close(sendInfo.c)
	sendInfo.isBusy = false
	sendInfo.Release()
}

func TestSendInfoPool_acquireBusy(t *testing.T) {
	defer func() {
		err := recover()
		assert.NotNil(t, err)
	}()

	pool := newSendInfoPool()
	sendInfo := pool.AcquireSendInfo(context.Background())
	close(sendInfo.c)
	sendInfo.Release()
	sendInfo.isBusy = true
	pool.AcquireSendInfo(context.Background())
}

func TestSendInfo_String(t *testing.T) {
	pool := newSendInfoPool()
	sendInfo0 := pool.AcquireSendInfo(context.Background())
	sendInfo1 := pool.AcquireSendInfo(context.Background())
	assert.Equal(t, sendInfo0.String(), sendInfo0.String())
	assert.NotEqual(t, sendInfo0.String(), sendInfo1.String())
}
