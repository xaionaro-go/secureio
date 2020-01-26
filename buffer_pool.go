package secureio

import (
	"fmt"
	"sync"
	"sync/atomic"
)

var (
	nextLockID uint64
)

type LockID uint64

type Buffer struct {
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

func (buf *Buffer) IsMonopolized() bool {
	return atomic.LoadUint32(&buf.isMonopolized) != 0
}

func (buf *Buffer) SetMonopolized(prevLockID LockID, isMonopolized bool) error {
	return buf.lockDo(prevLockID, func(LockID) {
		if isMonopolized {
			atomic.StoreUint32(&buf.isMonopolized, 1)
		} else {
			atomic.StoreUint32(&buf.isMonopolized, 0)
		}
	}, !isMonopolized)
}

func (buf *Buffer) LockDo(prevLockID LockID, fn func(LockID)) error {
	return buf.lockDo(prevLockID, fn, false)
}

func (buf *Buffer) lockDo(prevLockID LockID, fn func(LockID), ignoreIsMonopolized bool) error {
	var lockIDValue LockID
	if prevLockID != 0 && LockID(atomic.LoadUint64(&buf.lockID)) == prevLockID {
		lockIDValue = prevLockID
	} else {
		buf.locker.Lock()
		defer func() {
			atomic.StoreUint64(&buf.lockID, 0)
			buf.locker.Unlock()
		}()
		lockIDValue = LockID(atomic.AddUint64(&nextLockID, 1))
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
	fn(LockID(lockIDValue))
	if len(buf.Bytes) > maxPossiblePacketSize {
		panic(fmt.Sprintf(`should not happened: %v > %v`, len(buf.Bytes), maxPossiblePacketSize))
	}
	return nil
}

func (buf *Buffer) RLockDo(fn func()) error {
	buf.locker.RLock()
	defer buf.locker.RUnlock()
	fn()
	return nil
}

func (buf *Buffer) Read(b []byte) (int, error) {
	copy(b, buf.Bytes[buf.Offset:])
	buf.Offset += uint(len(b))
	return len(b), nil
}

func (buf *Buffer) Reset() {
	buf.Offset = 0
	buf.Bytes = buf.Bytes[:0]
	buf.MetadataVariableUInt = 0
}

func (buf *Buffer) Grow(size uint) {
	if uint(cap(buf.Bytes)) < size {
		buf.Bytes = make([]byte, size)
		return
	}

	buf.Bytes = buf.Bytes[:size]
}

func (buf *Buffer) Len() uint {
	return uint(len(buf.Bytes)) - buf.Offset
}

func (buf *Buffer) Cap() uint {
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
		buf := &Buffer{
			pool: pool,
		}
		buf.Grow(maxSize)
		return buf
	}
	return pool
}

func (pool *bufferPool) AcquireBuffer() *Buffer {
	buf := pool.storage.Get().(*Buffer)
	if buf.isBusy {
		panic(`should not happened`)
	}
	buf.isBusy = true

	atomic.AddInt32(&buf.refCount, 1)
	return buf
}

func (buf *Buffer) incRefCount() bool {
	if atomic.AddInt32(&buf.refCount, 1) == 1 {
		// this item was already fully released, we cannot reuse it :(
		atomic.AddInt32(&buf.refCount, -1)
		return false
	}
	return true
}

func (buf *Buffer) Release() {
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
