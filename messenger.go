package cryptofilter

import (
	"errors"
)

var (
	ErrPartialWrite = errors.New("partial write")
)

type Handler interface {
	Handle([]byte) error
}

type Messenger struct {
	messageType MessageType
	sess        *Session
	handler     Handler
	isClosed    bool
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
	if w.isClosed {
		return nil
	}
	var err error
	w.isClosed = true
	if closer, ok := w.handler.(interface{ Close() error }); ok {
		err = closer.Close()
	}
	return err
}

func (w *Messenger) SetHandler(handler Handler) {
	w.handler = handler
}
