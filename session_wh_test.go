package secureio

import (
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	xerrors "github.com/xaionaro-go/errors"
)

func TestHandlerByFuncs_HandleError(t *testing.T) {
	h := handlerByFuncs{}
	err := errors.New("unit-test")
	h.HandleError(err)
	callbackCount := 0
	h.OnErrorFunc = func(inErr error) {
		assert.Equal(t, err, inErr)
		callbackCount++
	}
	h.HandleError(err)
	assert.Equal(t, 1, callbackCount)
}

func TestHandlerByFuncs_Handle(t *testing.T) {
	h := handlerByFuncs{}
	assert.NoError(t, h.Handle(nil))
	err := errors.New("unit-test")
	b := make([]byte, 10)
	rand.Read(b)
	h.HandleFunc = func(inBytes []byte) error {
		assert.Equal(t, b, inBytes)
		return err
	}
	assert.Equal(t, err, h.Handle(b).(*xerrors.Error).Deepest().Err)
}

func TestSession_checkMessagesChecksum_negative(t *testing.T) {
	assert.True(t, (&Session{}).checkMessagesChecksum(
		nil,
		&messagesContainerHeaders{},
		nil,
	).(*xerrors.Error).Has(ErrInvalidChecksum{}))
}

func TestSessionIDGetterType_Get(t *testing.T) {
	id0 := globalSessionIDGetter.Get()
	id1 := globalSessionIDGetter.Get()
	timeNow = func() time.Time {
		return time.Unix(0, 0)
	}
	assert.NotEqual(t, SessionID{}, id0)
	assert.NotEqual(t, id0, id1)
}
