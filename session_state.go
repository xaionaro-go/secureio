package secureio

import (
	"context"
	"sync/atomic"
)

// SessionState is the state of a Session. It describes
// what's going on right now with the Session.
type SessionState uint64

const (
	// SessionStateNew means the Session was just created and even
	// did not start it's routines.
	SessionStateNew = SessionState(iota)

	// SessionStateClosed means the session is already deattached from
	// the backend io.ReadWriteCloser, closed and cannot be used anymore.
	SessionStateClosed

	// SessionStateKeyExchanging is the state which follows after
	// SessionStateNew. it means the Session started it's routines
	// (including the key exchanger routine), but not yet successfully
	// exchanged with keys (at least once).
	SessionStateKeyExchanging

	// SessionStateEstablished means the Session successfully exchanged
	// with keys and currently operational.
	SessionStateEstablished

	// SessionStatePaused means the Session was temporary detached from
	// the backend io.ReadWriteCloser by method `(*Session).SetPause`.
	SessionStatePaused

	// SessionStateClosing is a transition state to SessionStateClosed
	SessionStateClosing
)

type sessionStateStorage struct {
	SessionState

	changeChan       chan struct{}
	changeChanLocker lockerRWMutex
}

func newSessionStateStorage() *sessionStateStorage {
	return &sessionStateStorage{
		SessionState: SessionStateNew,
		changeChan:   make(chan struct{}),
	}
}

func (state SessionState) String() string {
	switch state {
	case SessionStateNew:
		return `new`
	case SessionStateClosed:
		return `closed`
	case SessionStateKeyExchanging:
		return `key_exchanging`
	case SessionStateEstablished:
		return `established`
	case SessionStatePaused:
		return `paused`
	case SessionStateClosing:
		return `closing`
	}
	return `unknown`
}

func (stateStor *sessionStateStorage) WaitFor(ctx context.Context, states ...SessionState) SessionState {
	for {
		var changeChan chan struct{}
		stateStor.changeChanLocker.RLockDo(func() {
			changeChan = stateStor.changeChan
		})
		loadedState := stateStor.Load()
		for i := 0; i < len(states); i++ {
			if loadedState == states[i] {
				return loadedState
			}
		}
		select {
		case <-ctx.Done():
			return loadedState
		case <-changeChan:
		}
	}
}

// Load atomically returns the currents state
func (state *SessionState) Load() SessionState {
	return SessionState(atomic.LoadUint64((*uint64)(state)))
}

func (stateStor *sessionStateStorage) Set(newState SessionState, cancelOnStates ...SessionState) (oldState SessionState) {
	stateStor.changeChanLocker.LockDo(func() {
		oldState = stateStor.Load()

		for i := 0; i < len(cancelOnStates); i++ {
			if oldState == cancelOnStates[i] {
				return
			}
		}

		atomic.StoreUint64((*uint64)(&stateStor.SessionState), uint64(newState))

		close(stateStor.changeChan)
		stateStor.changeChan = make(chan struct{})
	})
	return
}
