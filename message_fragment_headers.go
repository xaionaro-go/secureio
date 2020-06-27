package secureio

import (
	"encoding/binary"
	"sync"
)

var (
	messageFragmentHeadersSize = uint(binary.Size(messageFragmentHeadersData{}))
)

type messageFragmentHeaders struct {
	messageFragmentHeadersData
	pool   *messageFragmentHeadersPool
	isBusy bool
}

type messageFragmentHeadersData struct {
	ChainID            uint64
	StartPos           uint64
	TotalMessageLength uint64
}

type messageFragmentHeadersPool struct {
	storage sync.Pool
}

func newMessageFragmentHeadersPool() *messageFragmentHeadersPool {
	pool := &messageFragmentHeadersPool{}
	pool.storage.New = func() interface{} {
		msg := &messageFragmentHeaders{
			pool: pool,
		}
		return msg
	}
	return pool
}

func (hdr *messageFragmentHeadersData) Set(chainID, startPos, totalLength uint64) {
	hdr.ChainID = chainID
	hdr.StartPos = startPos
	hdr.TotalMessageLength = totalLength
}

func (pool *messageFragmentHeadersPool) AcquireMessageFragmentHeaders() *messageFragmentHeaders {
	hdr := pool.storage.Get().(*messageFragmentHeaders)
	if hdr.isBusy {
		panic(`should not happened`)
	}
	hdr.isBusy = true
	return hdr
}

func (hdr *messageFragmentHeadersData) Write(b []byte) (int, error) {
	if uint(len(b)) < messageFragmentHeadersSize {
		return 0, newErrTooShort(messageFragmentHeadersSize, uint(len(b)))
	}

	binaryOrderType.PutUint64(b[0:], hdr.ChainID)
	b = b[8:]
	binaryOrderType.PutUint64(b[0:], hdr.StartPos)
	b = b[8:]
	binaryOrderType.PutUint64(b[0:], hdr.TotalMessageLength)
	b = b[8:]

	return int(messageFragmentHeadersSize), nil
}

func (hdr *messageFragmentHeadersData) Read(b []byte) (int, error) {
	if uint(len(b)) < messageFragmentHeadersSize {
		return 0, newErrTooShort(messageFragmentHeadersSize, uint(len(b)))
	}

	hdr.ChainID = binaryOrderType.Uint64(b[0:])
	b = b[8:]
	hdr.StartPos = binaryOrderType.Uint64(b[0:])
	b = b[8:]
	hdr.TotalMessageLength = binaryOrderType.Uint64(b[0:])
	b = b[8:]

	return int(messageFragmentHeadersSize), nil
}

func (pool *messageFragmentHeadersPool) Put(hdr *messageFragmentHeaders) {
	if hdr == nil || !hdr.isBusy {
		panic(`should not happened`)
	}
	hdr.Reset()
	hdr.isBusy = false
	pool.storage.Put(hdr)
}

func (hdr *messageFragmentHeaders) Reset() {
	hdr.ChainID = 0
	hdr.StartPos = 0
	hdr.TotalMessageLength = 0
}

func (hdr *messageFragmentHeaders) Release() {
	hdr.pool.Put(hdr)
}
