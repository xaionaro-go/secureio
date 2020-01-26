package secureio

import (
	"sync"
)

type ReadItem struct {
	Data []byte

	isBusy bool
	pool   *readItemPool
}

type readItemPool struct {
	storage sync.Pool
}

func newReadItemPool() *readItemPool {
	pool := &readItemPool{}
	pool.storage = sync.Pool{
		New: func() interface{} {
			return &ReadItem{
				pool: pool,
			}
		},
	}
	return pool
}

func (pool *readItemPool) AcquireReadItem(maxSize uint32) *ReadItem {
	item := pool.storage.Get().(*ReadItem)
	if item.isBusy {
		panic(`should not happened`)
	}
	item.isBusy = true
	if cap(item.Data) < int(maxSize) {
		item.Data = make([]byte, 0, maxSize)
	}
	return item
}

func (pool *readItemPool) Put(freeReadItem *ReadItem) {
	if !freeReadItem.isBusy {
		panic(`should not happened`)
	}
	freeReadItem.isBusy = false
	freeReadItem.Data = freeReadItem.Data[:0]
	pool.storage.Put(freeReadItem)

}

func (it *ReadItem) Release() {
	it.pool.Put(it)
}
