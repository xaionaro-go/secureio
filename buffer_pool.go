package secureio

import (
	"fmt"
	"sync"
	"sync/atomic"
)

var (
	nextLockID uint64
)

type lockID uint64

type buffer struct {
	pool          *bufferPool
	locker        sync.RWMutex
	isMonopolized uint32
	isBusy        bool
	lockID        uint64
	refCount      int32

	Bytes  []byte
	Offset uint

	MetadataVariableUInt uint
}

func (buf *buffer) IsMonopolized() bool {
	return atomic.LoadUint32(&buf.isMonopolized) != 0
}

func (buf *buffer) SetMonopolized(prevLockID lockID, isMonopolized bool) error {
	return buf.lockDo(prevLockID, func(lockID) {
		if isMonopolized {
			atomic.StoreUint32(&buf.isMonopolized, 1)
		} else {
			atomic.StoreUint32(&buf.isMonopolized, 0)
		}
	}, !isMonopolized)
}

func (buf *buffer) LockDo(prevLockID lockID, fn func(lockID)) error {
	return buf.lockDo(prevLockID, fn, false)
}

func (buf *buffer) lockDo(prevLockID lockID, fn func(lockID), ignoreIsMonopolized bool) error {
	var lockIDValue lockID
	if prevLockID != 0 && lockID(atomic.LoadUint64(&buf.lockID)) == prevLockID {
		lockIDValue = prevLockID
	} else {
		buf.locker.Lock()
		defer func() {
			atomic.StoreUint64(&buf.lockID, 0)
			buf.locker.Unlock()
		}()
		lockIDValue = lockID(atomic.AddUint64(&nextLockID, 1))
		atomic.StoreUint64(&buf.lockID, uint64(lockIDValue))
	}

	if !buf.isBusy {
		panic(`should not happened`)
	}
	if !ignoreIsMonopolized && buf.IsMonopolized() {
		return newErrMonopolized()
	}

	if len(buf.Bytes) > maxPossiblePacketSize {
		panic(fmt.Sprintf(`should not happened: %v > %v`, len(buf.Bytes), maxPossiblePacketSize))
	}
	fn(lockID(lockIDValue))
	if len(buf.Bytes) > maxPossiblePacketSize {
		panic(fmt.Sprintf(`should not happened: %v > %v`, len(buf.Bytes), maxPossiblePacketSize))
	}
	return nil
}

func (buf *buffer) RLockDo(fn func()) error {
	buf.locker.RLock()
	defer buf.locker.RUnlock()
	fn()
	return nil
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
