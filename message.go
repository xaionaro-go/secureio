package cryptofilter

import (
	"unsafe"

	"github.com/xaionaro-go/bufling"
)

const (
	maxParallel    = 128
	maxPayloadSize = 1024
)

type messageType uint8

const (
	messageType_undefined     = iota
	messageType_keyExchange   = iota
	messageType_directPacket  = iota
	messageType_transitPacket = iota
)

type messageHeaders struct {
	Type     messageType
	Length   uint16
	Checksum uint32
}

var messageHeadersSize = unsafe.Sizeof(messageHeaders{})

func (msg *messageHeaders) Reset() {
	msg.Type = messageType_undefined
	msg.Length = 0
}

type messageWSlice struct {
	messageHeaders

	Payload []byte
}

func (msg *messageWSlice) Reset() {
	msg.messageHeaders.Reset()
	msg.Payload = nil
}

type message struct {
	messageHeaders

	Payload [maxPayloadSize]byte
}

var (
	messagesPool = bufling.NewAnyPool(maxParallel, func(buf *bufling.AnyBuffer) {
		buf.Buffer = &message{}
	})
	messagesWSlicePool = bufling.NewAnyPool(maxParallel, func(buf *bufling.AnyBuffer) {
		buf.Buffer = &messageWSlice{}
	})
)
