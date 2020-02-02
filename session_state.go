package secureio

import (
	mathRand "math/rand"
	"sync/atomic"
	"time"
)

type SessionState uint64

const (
	SessionState_new = SessionState(iota)
	SessionState_closed
	SessionState_keyExchanging
	SessionState_established
	SessionState_paused
	SessionState_closing
	sessionState_inTransition
)

func (state SessionState) String() string {
	switch state {
	case SessionState_new:
		return `new`
	case SessionState_closed:
		return `closed`
	case SessionState_keyExchanging:
		return `key_exchanging`
	case SessionState_established:
		return `established`
	case SessionState_paused:
		return `paused`
	case SessionState_closing:
		return `closing`
	case sessionState_inTransition:
		return `in_transition`
	}
	return `unknown`
}

func randSleep() {
	time.Sleep(time.Microsecond * time.Duration(mathRand.Intn(100)))
}

func (state *SessionState) WaitFor(states ...SessionState) SessionState {
	for {
		loadedState := state.Get()
		for i := 0; i < len(states); i++ {
			if loadedState == states[i] {
				return loadedState
			}
		}
		randSleep()
	}
}

func (state *SessionState) Load() SessionState {
	return SessionState(atomic.LoadUint64((*uint64)(state)))
}

func (state *SessionState) Get() (loadedState SessionState) {
	for {
		loadedState = SessionState(atomic.LoadUint64((*uint64)(state)))
		if loadedState != sessionState_inTransition {
			return
		}
		randSleep()
	}
}

func (state *SessionState) Set(newState SessionState, cancelOnStates ...SessionState) (oldState SessionState) {
	// Temporary changing the state to "inTransition"
	for {
		oldState = SessionState(atomic.SwapUint64((*uint64)(state), uint64(sessionState_inTransition)))
		if oldState != sessionState_inTransition {
			break
		}
		randSleep()
	}

	// Canceling if required
	for i := 0; i < len(cancelOnStates); i++ {
		if oldState == cancelOnStates[i] {
			for {
				if atomic.CompareAndSwapUint64((*uint64)(state), uint64(sessionState_inTransition), uint64(oldState)) {
					return
				}
				randSleep()
			}
		}
	}

	// Setting the new state
	for {
		if atomic.CompareAndSwapUint64((*uint64)(state), uint64(sessionState_inTransition), uint64(newState)) {
			return
		}
		randSleep()
	}
}
