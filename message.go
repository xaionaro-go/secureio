package secureio

import (
	"hash"
	"hash/crc32"
	"io"
	"sync"

	"github.com/xaionaro-go/errors"
)

var (
	ErrTooShort = errors.New(`too short`)
)

const (
	maxPayloadSize = 1 << 16
)

type MessageType uint16

const (
	MessageType_undefined = iota
	MessageType_keyExchange
	MessageType_dataPacketType0
	MessageType_dataPacketType1
	MessageType_dataPacketType2
	MessageType_dataPacketType3
	MessageType_dataPacketType4
	MessageType_dataPacketType5
	MessageType_dataPacketType6
	MessageType_dataPacketType7

	MessageTypeMax
)

type messageHeadersData struct {
	Type     MessageType
	Length   uint16
	Checksum uint32
}

type messageHeaders struct {
	messageHeadersData

	isBusy bool
}

var messageHeadersSize = 2 + 2 + 4

func (msg *messageHeadersData) Reset() {
	msg.Type = MessageType_undefined
	msg.Length = 0
	msg.Checksum = 0
}

type messageData struct {
	messageHeadersData

	Payload [maxPayloadSize]byte
}

type message struct {
	messageData

	isBusy bool
}

var (
	messagePool = sync.Pool{
		New: func() interface{} {
			return &message{}
		},
	}
	messageHeadersPool = sync.Pool{
		New: func() interface{} {
			return &messageHeaders{}
		},
	}
)

func acquireMessage() *message {
	msg := messagePool.Get().(*message)
	if msg.isBusy {
		panic(`should not happened`)
	}
	msg.isBusy = true
	return msg
}

func acquireMessageHeaders() *messageHeaders {
	hdr := messageHeadersPool.Get().(*messageHeaders)
	if hdr.isBusy {
		panic(`should not happened`)
	}
	hdr.isBusy = true
	return hdr
}

func (hdr *messageHeaders) Release() {
	if hdr == nil || !hdr.isBusy {
		panic(`should not happened`)
	}
	hdr.Reset()
	hdr.isBusy = false
	messageHeadersPool.Put(hdr)
}

var (
	crc32Pool = sync.Pool{
		New: func() interface{} {
			return crc32.NewIEEE()
		},
	}
)

func (hdr *messageHeadersData) Read(b []byte) (int, error) {
	if len(b) < messageHeadersSize {
		return 0, errors.Wrap(ErrTooShort)
	}
	hdr.Type = MessageType(binaryOrderType.Uint16(b[0:]))
	hdr.Length = binaryOrderType.Uint16(b[2:])
	hdr.Checksum = binaryOrderType.Uint32(b[4:])

	return messageHeadersSize, nil
}

func (hdr *messageHeadersData) Write(b []byte) (int, error) {
	if len(b) < messageHeadersSize {
		return 0, errors.Wrap(ErrTooShort)
	}

	binaryOrderType.PutUint16(b[0:], uint16(hdr.Type))
	binaryOrderType.PutUint16(b[2:], uint16(hdr.Length))
	binaryOrderType.PutUint32(b[4:], uint32(hdr.Checksum))

	return messageHeadersSize, nil
}

func (hdr *messageHeadersData) WriteTo(w io.Writer) (int, error) {
	var buf [8]byte

	n, err := hdr.Write(buf[:])
	if err != nil {
		return n, err
	}

	return w.Write(buf[:])
}

func (hdr *messageHeadersData) CalculateChecksum(payload []byte) error {
	checksumer := crc32Pool.Get().(hash.Hash32)
	err := func() (err error) {
		hdr.Checksum = 0
		_, err = hdr.WriteTo(checksumer)
		if err != nil {
			return errors.Wrap(err)
		}

		n, err := checksumer.Write(payload)
		if n != len(payload) && err == nil {
			err = errors.Wrap(ErrPartialWrite, n, len(payload))
		}
		if err != nil {
			return errors.Wrap(err)
		}

		hdr.Checksum = checksumer.Sum32()
		return
	}()
	checksumer.Reset()
	crc32Pool.Put(checksumer)

	return err
}

func (msg *message) Release() {
	if msg == nil || !msg.isBusy {
		panic(`should not happened`)
	}
	msg.Reset()
	msg.isBusy = false
	messagePool.Put(msg)
}
