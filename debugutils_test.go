package secureio

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCopyForDebug(t *testing.T) {
	items := copyForDebug(&SendInfo{refCount: 1}, &Session{id: SessionID{CreatedAt: 1}})
	sendInfo := items[0].(*SendInfo)
	session := items[1].(*Session)
	assert.Equal(t, int64(1), sendInfo.refCount)
	assert.Zero(t, session.id.CreatedAt)
}
