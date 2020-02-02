package secureio

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

type SendInfo struct {
	C      chan struct{}
	Err    error
	N      int
	SendID uint64 // for debug only

	ctx      context.Context
	refCount int32
	isBusy   bool
	pool     *sendInfoPool
}

var (
	nextSendID uint64
)

type sendInfoPool struct {
	storage sync.Pool
}

func newSendInfoPool() *sendInfoPool {
	pool := &sendInfoPool{}
	pool.storage = sync.Pool{
		New: func() interface{} {
			return &SendInfo{
				C:      make(chan struct{}),
				SendID: atomic.AddUint64(&nextSendID, 1),

				pool: pool,
			}
		},
	}
	return pool
}

func (pool *sendInfoPool) AcquireSendInfo(ctx context.Context) *SendInfo {
	sendInfo := pool.storage.Get().(*SendInfo)
	if sendInfo.isBusy {
		panic(`should not happened`)
	}
	sendInfo.isBusy = true
	sendInfo.incRefCount()
	sendInfo.C = make(chan struct{})
	sendInfo.SendID = atomic.AddUint64(&nextSendID, 1)
	sendInfo.ctx = ctx
	return sendInfo
}

func (pool *sendInfoPool) Put(freeSendInfo *SendInfo) {
	if !freeSendInfo.isBusy {
		panic(fmt.Sprintf(`should not happened (isBusy == %v)`,
			freeSendInfo.isBusy))
	}
	freeSendInfo.isBusy = false
	freeSendInfo.reset()
	pool.storage.Put(freeSendInfo)
}

func (sendInfo *SendInfo) reset() {
	sendInfo.Err = nil
	sendInfo.N = 0
}

func (sendInfo *SendInfo) incRefCount() {
	atomic.AddInt32(&sendInfo.refCount, 1)
}

func (sendInfo *SendInfo) Release() {
	refCount := atomic.AddInt32(&sendInfo.refCount, -1)
	if refCount != 0 {
		return
	}
	if refCount < 0 {
		panic(fmt.Sprintf(`should not happened (refCount == %v)`,
			refCount))
	}
	sendInfo.pool.Put(sendInfo)
}

func (sendInfo *SendInfo) String() string {
	return fmt.Sprintf("{C: %v; Err: %v: N: %v: SendID: %v, refCount: %v, isBusy: %v}",
		sendInfo.C, sendInfo.Err, sendInfo.N, sendInfo.SendID, atomic.LoadInt32(&sendInfo.refCount), sendInfo.isBusy)
}
func (sendInfo *SendInfo) Wait() {
	<-sendInfo.C

	/*select {
	case <-sendInfo.C:
	case <-sendInfo.ctx.Done():
		sendInfo.N = 0
		sendInfo.Err = newErrAlreadyClosed()
	}*/
}
