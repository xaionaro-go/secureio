package secureio

import (
	"sync"
	"sync/atomic"
)

// Handler is an interface defines a custom Handler of receiving
// traffic for a Messenger.
type Handler interface {
	// Handler is the function called each time to Handler an incoming message
	Handle([]byte) error
}

// Messenger is a Handler for a specific MessageType and for a specific Session.
type Messenger struct {
	messageType MessageType
	sess        *Session
	handler     Handler
	isClosed    uint32
	wg          sync.WaitGroup
}

func newMessenger(msgType MessageType, sess *Session) *Messenger {
	messenger := &Messenger{
		messageType: msgType,
		sess:        sess,
	}
	messenger.wg.Add(1)
	return messenger
}

// Write sends a message of MessageType assigned to the Messenger
// through the Session of this Messenger in the synchronous way.
func (messenger *Messenger) Write(p []byte) (int, error) {
	return messenger.sess.WriteMessage(messenger.messageType, p)
}

// WriteAsync sends a message of MessageType assigned to the Messenger
// through the Session of this Messenger in the asynchronous way.
func (messenger *Messenger) WriteAsync(p []byte) *SendInfo {
	return messenger.sess.WriteMessageAsync(messenger.messageType, p)
}

func (messenger *Messenger) handle(b []byte) error {
	return messenger.handler.Handle(b)
}

// Close closes the defined Handler.
//
// See `(*Messenger).SetHandler`
func (messenger *Messenger) Close() error {
	if atomic.SwapUint32(&messenger.isClosed, 1) != 0 {
		return nil
	}
	var err error
	if closer, ok := messenger.handler.(interface{ Close() error }); ok {
		err = closer.Close()
	}
	messenger.wg.Done()
	return err
}

// SetHandler sets the handler for incoming traffic.
func (messenger *Messenger) SetHandler(handler Handler) {
	messenger.handler = handler
}

// WaitForClosure waits until the Messenger will be closed and will finish
// everything.
func (messenger *Messenger) WaitForClosure() {
	messenger.wg.Wait()
}

type dummyMessenger struct {
}

func (d dummyMessenger) Write(p []byte) (int, error) {
	return len(p), nil
}

func (d dummyMessenger) Handle(p []byte) error {
	return nil
}
