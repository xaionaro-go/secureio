package secureio

import (
	"sync"
)

type readItem struct {
	Data []byte

	isBusy       bool
	isOneTimeUse bool
	pool         *readItemPool
}

type readItemPool struct {
	storage sync.Pool
}

func newReadItemPool() *readItemPool {
	pool := &readItemPool{}
	pool.storage = sync.Pool{
		New: func() interface{} {
			return &readItem{
				pool: pool,
			}
		},
	}
	return pool
}

func (pool *readItemPool) AcquireReadItem(maxSize uint32, isOneTimeUse bool) *readItem {
	var item *readItem
	if isOneTimeUse {
		item = &readItem{
			pool: pool,
		}
	} else {
		item = pool.storage.Get().(*readItem)
	}
	if item.isBusy {
		panic(`should not happened`)
	}
	item.isBusy = true
	if cap(item.Data) < int(maxSize) {
		item.Data = make([]byte, 0, maxSize)
	}
	return item
}

func (pool *readItemPool) Put(freeReadItem *readItem) {
	if !freeReadItem.isBusy {
		panic(`should not happened`)
	}
	if freeReadItem.isOneTimeUse {
		return
	}
	freeReadItem.isBusy = false
	freeReadItem.Data = freeReadItem.Data[:0]
	pool.storage.Put(freeReadItem)

}

func (it *readItem) Release() {
	it.pool.Put(it)
}
