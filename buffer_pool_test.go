package secureio

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testBufferPool = newBufferPool(64)

func TestBuffer_RLockDo(t *testing.T) {
	buf := testBufferPool.AcquireBuffer()
	defer buf.Release()

	assert.NoError(t, buf.RLockDo(func() {
		buf.locker.RUnlock()
		buf.locker.RLock()
	}))
}

func TestBuffer_Read(t *testing.T) {
	buf := testBufferPool.AcquireBuffer()
	defer buf.Release()

	buf.Grow(2)
	buf.Bytes[0] = 1
	buf.Bytes[1] = 2

	b := make([]byte, 1)
	n, err := buf.Read(b)
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, byte(1), b[0])

	n, err = buf.Read(b)
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, byte(2), b[0])
}

func TestBuffer_SetMonopolized(t *testing.T) {
	buf := testBufferPool.AcquireBuffer()
	defer buf.Release()

	assert.NoError(t, buf.SetMonopolized(0, true))
	assert.Error(t, buf.SetMonopolized(0, true))
	assert.NoError(t, buf.SetMonopolized(0, false))
	assert.Error(t, buf.SetMonopolized(0, false))
}

func TestBuffer_negative(t *testing.T) {
	pool := newBufferPool(64)
	buf := pool.AcquireBuffer()

	func() {
		defer func() {
			assert.NotNil(t, recover())
		}()
		buf.isBusy = false
		_ = buf.lockDo(0, func(id lockID) {}, false)
	}()
	buf.isBusy = true

	func() {
		defer func() {
			assert.NotNil(t, recover())
		}()

		buf.Bytes = make([]byte, maxPossiblePacketSize+1)
		_ = buf.lockDo(0, func(id lockID) {}, false)
	}()

	func() {
		defer func() {
			assert.NotNil(t, recover())
		}()

		buf.Bytes = nil
		_ = buf.lockDo(0, func(id lockID) {
			buf.Bytes = make([]byte, maxPossiblePacketSize+1)
		}, false)
	}()

	buf.Release()
	func() {
		defer func() {
			assert.NotNil(t, recover())
		}()

		buf.isBusy = true
		pool.AcquireBuffer()
	}()
	buf.isBusy = false
	buf = pool.AcquireBuffer()
	buf.Release()

	assert.False(t, buf.incRefCount())

	buf = pool.AcquireBuffer()
	func() {
		defer func() {
			assert.NotNil(t, recover())
		}()

		buf.isBusy = false
		buf.Release()
	}()
}
