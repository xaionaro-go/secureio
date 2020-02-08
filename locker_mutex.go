package secureio

import (
	"sync"
)

type lockerMutex struct {
	sync.Mutex
}

func (locker *lockerMutex) LockDo(fn func()) {
	locker.Lock()
	defer locker.Unlock()

	fn()
}

type lockerRWMutex struct {
	sync.RWMutex
}

func (locker *lockerRWMutex) LockDo(fn func()) {
	locker.Lock()
	defer locker.Unlock()

	fn()
}

func (locker *lockerRWMutex) RLockDo(fn func()) {
	locker.RLock()
	defer locker.RUnlock()

	fn()
}
