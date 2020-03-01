package secureio_test

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"

	"github.com/xaionaro-go/errors"

	. "github.com/xaionaro-go/secureio"
)

const (
	testUseUnixSocket = true
)

type testLogger struct {
	*testing.T
	Session *Session
}

func (l *testLogger) Error(sess *Session, err error) bool {
	xerr := err.(*errors.Error)
	if xerr.Has(&net.OpError{}) {
		fmt.Printf("D:%v:SID:%v: network error %v\n",
			l.T.Name(), sess.ID().CreatedAt%1000000, xerr)
		return true // For test TestMissedKeySeedMessage
	}
	if xerr.Has(io.EOF) || xerr.Has(ErrAlreadyClosed{}) {
		return false
	}
	l.T.Errorf("E:%v:SID:%v:%v", l.T.Name(), sess.ID().CreatedAt%1000000, xerr)
	return false
}
func (l *testLogger) OnConnect(sess *Session) {
}
func (l *testLogger) OnInit(sess *Session) {
	l.Session = sess
}

var testPairMutex sync.Mutex

var enableTestLoggers bool

func printLogsOfSession(t *testing.T, infoAsError bool, sess *Session) {
	if enableTestLoggers {
		fmt.Println("runned loggers")
	}
	go func() {
		if enableTestLoggers {
			defer fmt.Println("stopped debug logger")
		}
		for {
			select {
			case debugOutput, ok := <-sess.DebugOutputChan():
				if !ok {
					return
				}
				if !enableTestLoggers {
					return
				}
				fmt.Printf("D:%v:SID:%v: "+debugOutput.Format+"\n",
					append([]interface{}{t.Name(), sess.ID().CreatedAt % 1000000}, debugOutput.Args...)...)
			}
		}
	}()
	go func() {
		if enableTestLoggers {
			defer fmt.Println("stopped info logger")
		}
		for {
			select {
			case infoOutput, ok := <-sess.InfoOutputChan():
				if !ok {
					return
				}
				if !infoAsError {
					if !enableTestLoggers {
						return
					}
					fmt.Printf("I:%v:SID:%v: "+infoOutput.Format+"\n",
						append([]interface{}{t.Name(), sess.ID().CreatedAt % 1000000}, infoOutput.Args...)...)
					return
				}
				t.Errorf("[I] "+infoOutput.Format, infoOutput.Args...)
			}
		}
	}()
}

var testPipeCounter uint64

//go:norace
func testPair(t *testing.T) (identity0, identity1 *Identity, conn0, conn1 *net.UnixConn) {
	var err error

	if t == nil {
		t = &testing.T{}
	}

	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	keyRand := rand.New(rand.NewSource(0))

	_, key0, err := ed25519.GenerateKey(keyRand)
	assert.NoError(t, err)
	identity0, err = NewIdentityFromPrivateKey(key0)
	if err != nil {
		t.Fatal(err)
	}

	_, key1, err := ed25519.GenerateKey(keyRand)
	assert.NoError(t, err)
	identity1, err = NewIdentityFromPrivateKey(key1)
	if err != nil {
		t.Fatal(err)
	}

	testPairMutex.Lock()
	defer testPairMutex.Unlock()

	sockPath := fmt.Sprintf(`/tmp/xaionaro-go-secureio-%d-%d-0.sock`, os.Getpid(), atomic.AddUint64(&testPipeCounter, 1))
	_ = os.Remove(sockPath)

	l0, err := net.Listen(`unixpacket`, sockPath)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup

	var conn0i, conn1i net.Conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn1i, err = net.Dial(`unixpacket`, sockPath)
		if err != nil {
			t.Fatal(err)
		}
	}()

	conn0i, err = l0.Accept()
	if err != nil {
		t.Fatal(err)
	}

	wg.Wait()

	conn0 = conn0i.(*net.UnixConn)
	conn1 = conn1i.(*net.UnixConn)

	return
}

func testConnIsOpen(t *testing.T, conn0, conn1 io.ReadWriteCloser) {
	b := []byte(`test`)
	_, err := conn0.Write(b)
	if !assert.NoError(t, err) {
		return
	}

	_, err = conn1.Write(b)
	if !assert.NoError(t, err) {
		return
	}

	readBuf := make([]byte, 65536)

	for {
		n, err := conn0.Read(readBuf)
		if !assert.NoError(t, err) {
			return
		}
		if bytes.Compare(readBuf[:n], []byte(`test`)) == 0 {
			break
		}
	}

	for {
		n, err := conn1.Read(readBuf)
		if !assert.NoError(t, err) {
			return
		}
		if bytes.Compare(readBuf[:n], []byte(`test`)) == 0 {
			break
		}
	}
}

type dummyEventHandler struct{}

func (h *dummyEventHandler) OnInit(*Session)            {}
func (h *dummyEventHandler) OnConnect(*Session)         {}
func (h *dummyEventHandler) IsDebugEnabled() bool       { return false }
func (h *dummyEventHandler) Error(*Session, error) bool { return false }

type errorHandlerWrapper struct {
	EventHandler
	ErrorHandler func(*Session, error) bool
}

func wrapErrorHandler(
	eventHandler EventHandler,
	errorHandler func(*Session, error) bool,
) EventHandler {
	if eventHandler == nil {
		eventHandler = &dummyEventHandler{}
	}
	return &errorHandlerWrapper{eventHandler, errorHandler}
}

func (wrapper *errorHandlerWrapper) Error(sess *Session, err error) bool {
	return wrapper.ErrorHandler(sess, err)
}

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
