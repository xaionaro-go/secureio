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
