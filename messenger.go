package secureio

import (
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
}

func newMessenger(msgType MessageType, sess *Session) *Messenger {
	return &Messenger{
		messageType: msgType,
		sess:        sess,
	}
}

// Write sends a message of MessageType assigned to the Messenger
// through the Session of this Messenger in the synchronous way.
func (w *Messenger) Write(p []byte) (int, error) {
	return w.sess.WriteMessage(w.messageType, p)
}

// WriteAsync sends a message of MessageType assigned to the Messenger
// through the Session of this Messenger in the asynchronous way.
func (w *Messenger) WriteAsync(p []byte) *SendInfo {
	return w.sess.WriteMessageAsync(w.messageType, p)
}

func (w *Messenger) handle(b []byte) error {
	return w.handler.Handle(b)
}

// Close closes the defined Handler.
//
// See `(*Messenger).SetHandler`
func (w *Messenger) Close() error {
	if atomic.SwapUint32(&w.isClosed, 1) != 0 {
		return nil
	}
	var err error
	if closer, ok := w.handler.(interface{ Close() error }); ok {
		err = closer.Close()
	}
	return err
}

// SetHandler sets the handler for incoming traffic.
func (w *Messenger) SetHandler(handler Handler) {
	w.handler = handler
}

type dummyMessenger struct {
}

func (d dummyMessenger) Write(p []byte) (int, error) {
	return len(p), nil
}

func (d dummyMessenger) Handle(p []byte) error {
	return nil
}
