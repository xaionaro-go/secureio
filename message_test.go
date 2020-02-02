package secureio

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessagesContainerHeadersData_WriteRead(t *testing.T) {
	hdr := &messagesContainerHeaders{}

	copy(hdr.PacketID[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	hdr.Length = (^0) / 3
	copy(hdr.ContainerHeadersChecksum[:], []byte{17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	copy(hdr.MessagesChecksum[:], []byte{5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	hdr.MessagesContainerFlags = (^0) / 7
	hdr.Reserved0 = (^0) / 11
	hdr.Reserved1 = (^0) / 13

	buf := make([]byte, messagesContainerHeadersSize)
	{
		n, err := hdr.Write(buf)
		assert.NoError(t, err)
		assert.Equal(t, messagesContainerHeadersSize, uint(n))
	}

	hdrCopy := &messagesContainerHeaders{}
	{
		n, err := hdrCopy.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, messagesContainerHeadersSize, uint(n))
	}

	assert.Equal(t, hdr.messagesContainerHeadersData, hdrCopy.messagesContainerHeadersData)
}
