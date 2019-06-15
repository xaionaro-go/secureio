package cryptofilter

import (
	"errors"
	"io"
)

var (
	ErrPartialWrite = errors.New("partial write")
)

type Messenger struct {
	messageType MessageType
	sess        *Session
	handler     io.ReaderFrom
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

func (w *Messenger) ReadFrom(r io.Reader) (n int64, err error) {
	return w.handler.ReadFrom(r)
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

func (w *Messenger) SetHandler(handler io.ReaderFrom) {
	w.handler = handler
}
