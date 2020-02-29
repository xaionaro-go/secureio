package secureio

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionState_String(t *testing.T) {
	m := map[string]struct{}{}
	for sessState := SessionState(0); sessState < SessionState(^uint8(0)); sessState++ {
		s := sessState.String()
		if s == `unknown` {
			continue
		}
		_, alreadyExists := m[s]
		assert.False(t, alreadyExists)
		m[s] = struct{}{}
	}
}
