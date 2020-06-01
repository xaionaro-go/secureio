package secureio

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type muteEventHandler struct{}

func (h *muteEventHandler) OnConnect(*Session)         {}
func (h *muteEventHandler) IsDebugEnabled() bool       { return false }
func (h *muteEventHandler) Error(*Session, error) bool { return true }

func TestDummyEventHandler(t *testing.T) {
	sess := &Session{}
	sess.id = globalSessionIDGetter.Get()

	callbackCount := 0
	wrapErrorHandler(nil, func(inSess *Session, inErr error) bool {
		callbackCount++
		assert.Equal(t, sess, inSess)
		return false
	}).Error(sess, nil)
	assert.Equal(t, 1, callbackCount)

	wrapErrorHandler(&muteEventHandler{}, func(inSess *Session, inErr error) bool {
		panic("should not happen")
	}).Error(sess, nil)

	wrapErrorHandler(nil, nil).OnConnect(nil)
}
