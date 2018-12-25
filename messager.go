package cryptofilter

import (
	"encoding/binary"
	"hash/crc32"
	"io"
)

type messager struct {
	messageType messageType
	backend     io.ReadWriter
}

func (w *messager) Write(p []byte) (int, error) {
	if len(p) > maxPayloadSize {
		return 0, ErrTooBig
	}
	msgBuffer := messagesWSlicePool.Next()
	msg := msgBuffer.Buffer.(*messageWSlice)
	msg.Type = w.messageType
	msg.Length = uint16(len(p))
	msg.Checksum = crc32.ChecksumIEEE(p)
	msg.Payload = p

	err := binary.Write(w.backend, binary.BigEndian, msg)
	msgBuffer.Unlock()

	var n int
	if err == nil {
		n = len(p)
	}
	return n, err
}
