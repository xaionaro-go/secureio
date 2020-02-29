package secureio

import (
	"sync/atomic"
	"time"
	"unsafe"
)

type erroneousConn struct {
	errPtr *error
}

func newErroneousConn() *erroneousConn {
	return &erroneousConn{errPtr: &[]error{nil}[0]}
}

func (conn *erroneousConn) SetError(err error) {
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&conn.errPtr)), unsafe.Pointer(&err))
}

func (conn *erroneousConn) GetError() error {
	return *(*error)(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&conn.errPtr))))
}

func (conn *erroneousConn) Read([]byte) (int, error) {
	return 0, conn.GetError()
}

func (conn *erroneousConn) Write([]byte) (int, error) {
	return 0, conn.GetError()
}

func (conn *erroneousConn) Close() error {
	return conn.GetError()
}

func (conn *erroneousConn) SetDeadline(time.Time) error {
	return conn.GetError()
}
