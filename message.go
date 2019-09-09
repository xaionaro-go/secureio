package secureio

import (
	"encoding/binary"
	"hash"
	"hash/crc32"
	"sync"

	"github.com/xaionaro-go/errors"
)

const (
	maxPayloadSize = 1024
)

type MessageType uint8

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

var messageHeadersSize = binary.Size(messageHeaders{})

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

func (hdr *messageHeadersData) CalculateChecksum(payload []byte) error {
	checksumer := crc32Pool.Get().(hash.Hash32)
	err := func() (err error) {
		hdr.Checksum = 0
		err = binary.Write(checksumer, binaryOrderType, hdr)
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
