package cryptofilter

import (
	"errors"
	"io"
	"runtime"
	"sync"
)

var (
	ErrTooBig = errors.New("message is too big")
)

type Session struct {
	locker sync.RWMutex

	state        SessionState
	identity     *Identity
	keyExchanger *keyExchanger
	backend      io.ReadWriteCloser
	closeChan    chan struct{}
}

func (sess *Session) WaitForState(states ...SessionState) SessionState {
	return sess.state.WaitFor(states...)
}

func (sess *Session) GetState() SessionState {
	return sess.state.Get()
}

func (sess *Session) setState(state SessionState, cancelOnStates ...SessionState) (oldState SessionState) {
	return sess.state.Set(state, cancelOnStates...)
}

func panicIf(err error) {
	if err != nil {
		panic(err)
	}
}

func newSession(identity *Identity) *Session {
	sess := &Session{
		identity:  identity,
		closeChan: make(chan struct{}),
		state:     SessionState_closed,
	}
	panicIf(sess.init())
	return sess
}

func (sess *Session) init() error {
	return nil
}

func (sess *Session) isAlreadyLockedByMe() bool {
	pc := make([]uintptr, 8)
	l := runtime.Callers(1, pc)
	if l < 2 {
		panic("l < 2")
	}
	lockDoPtr := pc[0]
	for i := 1; i < l; i++ {
		if pc[i] == lockDoPtr {
			return true
		}
	}
	return false
}

func (sess *Session) LockDo(fn func()) {
	if !sess.isAlreadyLockedByMe() {
		sess.locker.Lock()
		defer sess.locker.Unlock()
	}
	fn()
}

func (sess *Session) Wrap(backend io.ReadWriteCloser) (result io.ReadWriteCloser) {
	sess.LockDo(func() {
		if sess.backend == backend {
			result = sess
			return
		}
		if sess.backend != nil {
			panic(`This shouldn't happened. One Session should be used only for one backend.`)
		}
		sess.setBackend(backend)
		result = sess
	})
	return
}

func (sess *Session) setBackend(backend io.ReadWriteCloser) {
	sess.LockDo(func() {
		sess.backend = backend
		sess.startKeyExchange()
	})
}

func (sess *Session) newMessanger(msgType messageType) io.ReadWriter {
	messanger := &messager{
		messageType: msgType,
		backend:     sess.backend,
	}
	sess.subscribeReader(messager, msgType)
	return messager
}

func (sess *Session) startKeyExchange() {
	switch sess.setState(SessionState_keyExchanging, SessionState_closing, SessionState_closed) {
	case SessionState_keyExchanging, SessionState_closing, SessionState_closed:
		return
	}

	sess.keyExchanger = newKeyExchanger(sess.newMessanger(messangeType_keyExchange), func(secret []byte) {
		// ok
		sess.setSecret(secret)
		sess.setState(SessionState_established)
	}, func(err error) {
		// got error
		sess.Close()
	})
}

func (sess *Session) read(p []byte) (int, error) {
}

func (sess *Session) Read(p []byte) (int, error) {
	switch sess.WaitForState(SessionState_established, SessionState_closing, SessionState_closed) {
	case SessionState_closed, SessionState_closing:
		return -1, ErrReadWhileSessionIsClosed
	}
	return sess.read(p)
}

func (sess *Session) write(p []byte) (int, error) {
}

func (sess *Session) Write(p []byte) (int, error) {
	switch sess.WaitForState(SessionState_established, SessionState_closing, SessionState_closed) {
	case SessionState_closed, SessionState_closing:
		return -1, ErrWriteWhileSessionIsClosed
	}
	return sess.write(p)
}

func (sess *Session) Close() error {
	switch sess.setState(SessionState_closing) {
	case SessionState_closed, SessionState_closing:
		return
	}
	sess.closeChan <- struct{}{}
	err := sess.backend.Close()
	sess.setState(SessionState_closed)
	return err
}
