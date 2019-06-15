package cryptofilter

import (
	"sync"
	"unsafe"
)

const (
	maxParallel    = 128
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

type messageHeaders struct {
	Type     MessageType
	Length   uint16
	Checksum uint32
}

var messageHeadersSize = unsafe.Sizeof(messageHeaders{})

func (msg *messageHeaders) Reset() {
	msg.Type = MessageType_undefined
	msg.Length = 0
	msg.Checksum = 0
}

type message struct {
	messageHeaders

	Payload [maxPayloadSize]byte
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

func newMessage() *message {
	return messagePool.Get().(*message)
}

func newMessageHeaders() *messageHeaders {
	return messageHeadersPool.Get().(*messageHeaders)
}

func (msg *messageHeaders) Release() {
	msg.Reset()
	messageHeadersPool.Put(msg)
}

func (msg *message) Release() {
	msg.Reset()
	messagePool.Put(msg)
}
