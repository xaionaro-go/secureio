package secureio

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMin(t *testing.T) {
	assert.Equal(t, -3, min(2, -3, 1))
}

func TestUMin(t *testing.T) {
	assert.Equal(t, uint(1), umin(2, 1, 3))
}
