package secureio

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xaionaro-go/iotools"
)

func dummySession(t *testing.T, errFunc func(error)) *Session {
	sess := &Session{}
	sess.init(&Identity{}, &Identity{}, iotools.NewReadWriteCloser(func(bytes []byte) (int, error) {
		t.Fatal("read", bytes)
		return len(bytes), nil
	}, func(bytes []byte) (int, error) {
		t.Fatal("write", bytes)
		return len(bytes), nil
	}, func() error {
		t.Fatal("close")
		return nil
	}), wrapErrorHandler(&dummyEventHandler{}, func(session *Session, err error) bool {
		errFunc(err)
		return false
	}), nil)
	sess.keyExchanger = &keyExchanger{}
	sess.ctx, sess.cancelFunc = context.WithCancel(context.Background())
	sess.delayedSendInfo = sess.sendInfoPool.AcquireSendInfo(sess.ctx)

	return sess
}

func TestNegotiator_StartClose(t *testing.T) {
	t.Run("doubleStart", func(t *testing.T) {
		sess := dummySession(t, func(err error) {})
		sess.setSecrets([][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)})
		n := newNegotiator(
			context.Background(),
			newMessenger(messageTypeNegotiation, sess),
			NegotiatorOptions{Enable: NegotiatorEnableTrue},
			func() {}, nil,
		)
		n.stageChan = make(chan struct{}, 2)
		err := n.Start()
		require.NoError(t, err)
		err = n.Start()
		require.Error(t, err)
		_ = sess.Close()
		err = n.Close()
		require.NoError(t, err)
	})

	t.Run("enable=auto", func(t *testing.T) {
		okCount := 0
		errCount := 0
		sess := dummySession(t, func(err error) {
			t.Fatal(err)
		})
		sess.setSecrets([][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)})
		n := newNegotiator(
			context.Background(),
			newMessenger(messageTypeNegotiation, sess),
			NegotiatorOptions{Enable: NegotiatorEnableAuto},
			func() {
				okCount++
			},
			func(err error) {
				errCount++
			},
		)
		n.stageChan = make(chan struct{}, 2)
		err := n.Start()
		require.NoError(t, err)
		_ = sess.Close()
		err = n.Close()
		require.NoError(t, err)
		require.Equal(t, 1, okCount)
		require.Zero(t, errCount)
	})

	t.Run("enable=true", func(t *testing.T) {
		okCount := 0
		errCount := 0
		sess := dummySession(t, func(err error) {
			errCount++
		})
		defer sess.Close()
		sess.setSecrets([][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)})
		n := newNegotiator(
			context.Background(),
			newMessenger(0, sess),
			NegotiatorOptions{Enable: NegotiatorEnableTrue},
			func() {
				okCount++
			},
			func(err error) {
				errCount++
			},
		)
		n.stageChan = make(chan struct{}, 2)
		err := n.Start()
		require.NoError(t, err)
		_ = sess.Close()
		err = n.Close()
		require.NoError(t, err)
		require.Zero(t, okCount)
	})

	t.Run("enable=false", func(t *testing.T) {
		okCount := 0
		errCount := 0
		sess := dummySession(t, func(err error) {
			t.Fatal(err)
		})
		sess.setSecrets([][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)})
		n := newNegotiator(
			context.Background(),
			newMessenger(messageTypeNegotiation, sess),
			NegotiatorOptions{Enable: NegotiatorEnableFalse},
			func() {
				okCount++
			},
			func(err error) {
				errCount++
			},
		)
		n.stageChan = make(chan struct{}, 2)
		err := n.Start()
		require.NoError(t, err)
		_ = sess.Close()
		err = n.Close()
		require.NoError(t, err)
		require.Equal(t, 1, okCount)
		require.Zero(t, errCount)
	})
}

func TestNegotiator_ctx(t *testing.T) {
	sess := dummySession(t, func(err error) {
		t.Fatal(err)
	})
	sess.setSecrets([][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)})
	ctx, cancelFn := context.WithCancel(context.Background())
	n := newNegotiator(
		ctx,
		newMessenger(messageTypeNegotiation, sess),
		NegotiatorOptions{Enable: NegotiatorEnableTrue},
		func() {
			t.Fatal("okFunc")
		},
		func(err error) {},
	)
	n.stageChan = make(chan struct{}, 2)
	cancelFn()
	err := n.Start()
	require.NoError(t, err)
	_ = sess.Close()
	err = n.Close()
	require.NoError(t, err)
}

func TestNegotiator_Handle(t *testing.T) {
	n := &negotiator{messenger: &Messenger{sess: &Session{}}}

	t.Run("negative_short", func(t *testing.T) {
		err := n.Handle([]byte{})
		require.Error(t, err)
		require.True(t, errors.As(err, &ErrTooShort{}))
	})

	t.Run("negative_unknownSubType", func(t *testing.T) {
		err := n.Handle([]byte{255})
		require.Error(t, err)
		require.True(t, errors.As(err, &errUnknownSubType{}))
	})
}

func TestNegotiator_parseMessage(t *testing.T) {
	n := &negotiator{}

	t.Run("negative_short", func(t *testing.T) {
		err := n.parseMessage(&negotiationPingPongMessage{}, nil)
		require.Error(t, err)
		require.True(t, errors.As(err, &ErrTooShort{}))
	})
}

func TestNegotiator_handleControlMessage(t *testing.T) {
	n := &negotiator{}

	t.Run("negative_short", func(t *testing.T) {
		err := n.handleControlMessage(nil)
		require.Error(t, err)
		require.True(t, errors.As(err, &ErrTooShort{}))
	})
}

func TestNegotiator_handlePingPongMessage(t *testing.T) {
	n := &negotiator{messenger: &Messenger{sess: &Session{}}}

	t.Run("negative_short", func(t *testing.T) {
		err := n.handlePingPongMessage(nil, false)
		require.Error(t, err)
		require.True(t, errors.As(err, &ErrTooShort{}))
	})

	t.Run("negative_invalidChecksum", func(t *testing.T) {
		msg := negotiationPingPongMessage{
			MessageSubType: 2,
		}
		var buf bytes.Buffer
		binary.Write(&buf, binaryOrderType, &msg)
		err := n.handlePingPongMessage(buf.Bytes(), false)
		require.Error(t, err)
		require.True(t, errors.As(err, &ErrInvalidChecksum{}))
	})
}
