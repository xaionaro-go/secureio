package secureio

import (
	"fmt"
	"sync"
	"sync/atomic"
)

type buffer struct {
	locker lockerRWMutex

	pool          *bufferPool
	isMonopolized uint32
	isBusy        bool
	lockID        uint64
	refCount      int32

	Bytes  []byte
	Offset uint

	MetadataVariableUInt uint
}

func (buf *buffer) LockDo(fn func()) {
	if !buf.isBusy {
		panic(`should not happen`)
	}
	buf.locker.LockDo(fn)
}

func (buf *buffer) Lock() {
	if !buf.isBusy {
		panic(`should not happen`)
	}
	buf.locker.Lock()
}

func (buf *buffer) Unlock() {
	buf.locker.Unlock()
}

func (buf *buffer) Read(b []byte) (int, error) {
	copy(b, buf.Bytes[buf.Offset:])
	buf.Offset += uint(len(b))
	return len(b), nil
}

func (buf *buffer) Reset() {
	buf.Offset = 0
	buf.Bytes = buf.Bytes[:0]
	buf.MetadataVariableUInt = 0
}

func (buf *buffer) Grow(size uint) {
	if uint(cap(buf.Bytes)) < size {
		buf.Bytes = make([]byte, size)
		return
	}

	buf.Bytes = buf.Bytes[:size]
}

func (buf *buffer) Len() uint {
	return uint(len(buf.Bytes)) - buf.Offset
}

func (buf *buffer) Cap() uint {
	return uint(cap(buf.Bytes))
}

type bufferPool struct {
	storage sync.Pool
}

func newBufferPool(maxSize uint) *bufferPool {
	pool := &bufferPool{
		storage: sync.Pool{},
	}
	pool.storage.New = func() interface{} {
		buf := &buffer{
			pool: pool,
		}
		buf.Grow(maxSize)
		return buf
	}
	return pool
}

func (pool *bufferPool) AcquireBuffer() *buffer {
	buf := pool.storage.Get().(*buffer)
	if buf.isBusy {
		panic(`should not happened`)
	}
	buf.isBusy = true

	atomic.AddInt32(&buf.refCount, 1)
	return buf
}

func (buf *buffer) incRefCount() bool {
	if atomic.AddInt32(&buf.refCount, 1) == 1 {
		// this item was already fully released, we cannot reuse it :(
		atomic.AddInt32(&buf.refCount, -1)
		return false
	}
	return true
}

func (buf *buffer) Release() {
	refCount := atomic.AddInt32(&buf.refCount, -1)
	if refCount > 0 {
		return
	}
	if refCount < 0 || !buf.isBusy {
		panic(fmt.Sprintf(`should not happened (refCount == %v; isBusy == %v)`,
			refCount, buf.isBusy))
	}
	buf.Reset()
	buf.isBusy = false
	buf.isMonopolized = 0
	buf.lockID = 0
	buf.pool.storage.Put(buf)
}
