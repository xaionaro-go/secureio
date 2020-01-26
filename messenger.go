package secureio

import (
	"sync/atomic"
)

type Handler interface {
	Handle([]byte) error
}

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

func (w *Messenger) Write(p []byte) (int, error) {
	return w.sess.WriteMessage(w.messageType, p)
}

func (w *Messenger) Handle(b []byte) error {
	return w.handler.Handle(b)
}

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

func (w *Messenger) SetHandler(handler Handler) {
	w.handler = handler
}

type DummyMessenger struct {
}

func (d DummyMessenger) Write(p []byte) (int, error) {
	return len(p), nil
}

func (d DummyMessenger) Handle(p []byte) error {
	return nil
}
