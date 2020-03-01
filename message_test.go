package secureio

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xaionaro-go/unsafetools"

	xerrors "github.com/xaionaro-go/errors"
)

func TestMessagesContainerHeadersData_WriteRead(t *testing.T) {
	hdr := &messagesContainerHeaders{}

	copy(hdr.PacketID[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	hdr.Length = (^0) / 3
	copy(hdr.ContainerHeadersChecksum[:], []byte{17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	copy(hdr.MessagesChecksum[:], []byte{5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})

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

func TestMessageType_String_Duplicates(t *testing.T) {
	m := map[string]struct{}{}
	for msgType := MessageType(0); msgType < MessageType(^uint8(0)); msgType++ {
		s := msgType.String()
		if s == `unknown` {
			continue
		}
		_, alreadyExists := m[s]
		assert.False(t, alreadyExists)
		m[s] = struct{}{}
	}
}

func TestPacketID_String(t *testing.T) {
	assert.Equal(t, "", (*packetID)(nil).String())
	assert.NotEqual(t, "", (&packetID{}).String())
}

func TestMessagesContainerHeadersData_WriteTo(t *testing.T) {
	containerHdr := newMessagesContainerHeadersPool().AcquireMessagesContainerHeaders(&Session{})
	defer containerHdr.Release()

	_, err := rand.Read(unsafetools.BytesOf(&containerHdr.messagesContainerHeadersData))
	assert.NoError(t, err)

	var buf bytes.Buffer
	_, err = containerHdr.WriteTo(&buf)
	assert.NoError(t, err)

	var containerHdrDup messagesContainerHeaders
	_, err = containerHdrDup.Read(buf.Bytes())
	assert.NoError(t, err)

	assert.Equal(t, containerHdr.messagesContainerHeadersData, containerHdrDup.messagesContainerHeadersData)
}

func TestPacketID_Read_negative(t *testing.T) {
	_, err := (&packetID{}).Read(nil)
	assert.True(t, err.(*xerrors.Error).Has(ErrTooShort{}))
}

func TestPacketID_Write_negative(t *testing.T) {
	_, err := (&packetID{}).Write(nil)
	assert.True(t, err.(*xerrors.Error).Has(ErrTooShort{}))
}

func TestMessageHeadersPool_negative(t *testing.T) {
	pool := newMessageHeadersPool()
	hdr := pool.AcquireMessageHeaders()
	func() {
		defer func() {
			assert.NotNil(t, recover())
		}()
		hdr.isBusy = false
		hdr.Release()
	}()

	func() {
		defer func() {
			assert.NotNil(t, recover())
		}()
		hdr = pool.AcquireMessageHeaders()
		hdr.Release()
		hdr.isBusy = true
		pool.AcquireMessageHeaders()
	}()
}

func TestMessagesContainerHeadersPool_negative(t *testing.T) {
	pool := newMessagesContainerHeadersPool()
	sess := &Session{}
	containerHdr := pool.AcquireMessagesContainerHeaders(sess)
	func() {
		defer func() {
			assert.NotNil(t, recover())
		}()
		containerHdr.isBusy = false
		containerHdr.Release()
	}()

	func() {
		defer func() {
			assert.NotNil(t, recover())
		}()
		containerHdr = pool.AcquireMessagesContainerHeaders(sess)
		containerHdr.Release()
		containerHdr.isBusy = true
		pool.AcquireMessagesContainerHeaders(sess)
	}()
}

func TestMessageHeadersData_Read_negative(t *testing.T) {
	_, err := (&messageHeaders{}).Read(nil)
	assert.True(t, err.(*xerrors.Error).Has(ErrTooShort{}), err)
}

func TestMessageHeadersData_Write_negative(t *testing.T) {
	_, err := (&messageHeaders{}).Write(nil)
	assert.True(t, err.(*xerrors.Error).Has(ErrTooShort{}), err)
}

func TestMessagesContainerHeadersData_Read_negative(t *testing.T) {
	containerHdr := &messagesContainerHeaders{}
	_, err := containerHdr.Read(nil)
	assert.True(t, err.(*xerrors.Error).Has(ErrTooShort{}), err)
}

func TestMessagesContainerHeadersData_Write_negative(t *testing.T) {
	containerHdr := &messagesContainerHeaders{}
	_, err := containerHdr.Write(nil)
	assert.True(t, err.(*xerrors.Error).Has(ErrTooShort{}), err)

	writer := newErroneousConn()
	testErr := errors.New("unit-test")
	writer.SetError(testErr)
	_, err = containerHdr.WriteTo(writer)
	assert.Equal(t, testErr, err.(*xerrors.Error).Deepest().Err, err)
}
