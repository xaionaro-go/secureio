package secureio

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDummyMessenger(t *testing.T) {
	messenger := &dummyMessenger{}

	n, err := messenger.Write(make([]byte, 8))
	assert.NoError(t, err)
	assert.Equal(t, 8, n)

	err = messenger.Handle(make([]byte, 8))
	assert.NoError(t, err)
}
