package secureio

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/xaionaro-go/slice"
	"github.com/xaionaro-go/unsafetools"
	"golang.org/x/crypto/poly1305"
	"lukechampine.com/blake3"

	xerrors "github.com/xaionaro-go/errors"
)

const (
	maxPossiblePacketSize = 1<<16 - 256
)

const (
	ivSize = 24 // XChaCha20
)

var (
	maxPayloadSize uint32
)

func init() {
	SetMaxPayloadSize(uint32(maxPossiblePacketSize - messagesContainerHeadersSize - messageHeadersSize))
}

// SetMaxPayloadSize sets the default MaxPayloadSize.
//
// MaxPayloadSize is used to calculate the size of the buffers to be
// used to handle the communication. So you cannot send/read a message
// via a session larger than session's MaxPayloadSize
// (see `GetMaxPayloadSize`).
func SetMaxPayloadSize(newSize uint32) {
	newSize &= ^(uint32(aes.BlockSize) - 1)
	atomic.StoreUint32(&maxPayloadSize, newSize)
}

var (
	poly1305KeyXORer = []byte("github.com/xaionaro-go/secureio github.com/xaionaro-go/secureio github.com/xaionaro-go/secureio github.com/xaionaro-go/secureio")
)

// MessageType is the identifier of the type of the message.
// It is used to determine how to interpret the message (which Handler to use).
type MessageType uint8

const (
	messageTypeUndefined = iota
	messageTypeKeyExchange

	// MessageTypeDataPacketType0 is the default MessageType for
	// the in-band data. It used by default for (*Session).Read and
	// (*Session).Write.
	MessageTypeDataPacketType0

	// MessageTypeDataPacketType1 is a MessageType for a custom Handler.
	MessageTypeDataPacketType1

	// MessageTypeDataPacketType2 is a MessageType for a custom Handler.
	MessageTypeDataPacketType2

	// MessageTypeDataPacketType3 is a MessageType for a custom Handler.
	MessageTypeDataPacketType3

	// MessageTypeDataPacketType4 is a MessageType for a custom Handler.
	MessageTypeDataPacketType4

	// MessageTypeDataPacketType5 is a MessageType for a custom Handler.
	MessageTypeDataPacketType5

	// MessageTypeDataPacketType6 is a MessageType for a custom Handler.
	MessageTypeDataPacketType6

	// MessageTypeDataPacketType7 is a MessageType for a custom Handler.
	MessageTypeDataPacketType7

	// MessageTypeDataPacketType8 is a MessageType for a custom Handler.
	MessageTypeDataPacketType8

	// MessageTypeDataPacketType9 is a MessageType for a custom Handler.
	MessageTypeDataPacketType9

	// MessageTypeDataPacketType10 is a MessageType for a custom Handler.
	MessageTypeDataPacketType10

	// MessageTypeDataPacketType11 is a MessageType for a custom Handler.
	MessageTypeDataPacketType11

	// MessageTypeDataPacketType12 is a MessageType for a custom Handler.
	MessageTypeDataPacketType12

	// MessageTypeDataPacketType13 is a MessageType for a custom Handler.
	MessageTypeDataPacketType13

	// MessageTypeDataPacketType14 is a MessageType for a custom Handler.
	MessageTypeDataPacketType14

	// MessageTypeDataPacketType15 is a MessageType for a custom Handler.
	MessageTypeDataPacketType15

	// MessageTypeMax is supposed to be used as a loop limiter to
	// iterate over all message types. For example:
	//
	// ```
	// for msgType := MessageType(0); msgType < MessageTypeMax; msgType++ {
	//     [... some code here ...]
	// }
	// ```
	MessageTypeMax
)

func (t MessageType) String() string {
	switch {
	case t == messageTypeUndefined:
		return `undefined`
	case t == messageTypeKeyExchange:
		return `key_exchange`
	case t >= MessageTypeDataPacketType0 && t <= MessageTypeDataPacketType15:
		return fmt.Sprintf(`datatype%d`, uint8(t-MessageTypeDataPacketType0))
	}
	return `unknown`
}

type messageLength uint32

type messageHeadersData struct {
	Type      MessageType
	Reserved0 uint8
	Reserved1 uint16
	Length    messageLength
}

type messageHeaders struct {
	messageHeadersData

	pool   *messageHeadersPool
	isBusy bool
}

type messagesContainerFlags uint8

const (
	messagesContainerFlagsIsEncrypted = messagesContainerFlags(1 << iota)
)

func (flags messagesContainerFlags) IsEncrypted() bool {
	return flags&messagesContainerFlagsIsEncrypted != 0
}
func (flags *messagesContainerFlags) SetIsEncrypted(newValue bool) {
	if newValue {
		*flags |= messagesContainerFlagsIsEncrypted
	} else {
		*flags &= ^messagesContainerFlagsIsEncrypted
	}
}

type packetID [8]byte

func (id *packetID) Value() uint64 {
	return binaryOrderType.Uint64(id[:])
}
func (id *packetID) String() string {
	if id == nil {
		return ""
	}
	return fmt.Sprint(id.Value())
}
func (id *packetID) SetNextPacketID(sess *Session) {
	binaryOrderType.PutUint64((*id)[:], atomic.AddUint64(&sess.nextPacketID, 1))
}
func (id *packetID) Read(b []byte) (int, error) {
	if len(b) < len(*id) {
		return 0, newErrTooShort(uint(len(*id)), uint(len(b)))
	}
	copy((*id)[:], b)
	return len(*id), nil
}
func (id *packetID) Write(b []byte) (int, error) {
	if len(b) < len(*id) {
		return 0, newErrTooShort(uint(len(*id)), uint(len(b)))
	}
	copy(b, (*id)[:])
	return len(*id), nil
}

type messagesContainerHeadersData struct {
	PacketID packetID // Should be the first. It is used to decrypt other values!

	ContainerHeadersChecksum [poly1305.TagSize]byte
	MessagesChecksum         [poly1305.TagSize]byte
	Length                   messageLength
	messagesContainerFlags
	Reserved0 uint8
	Reserved1 uint16
}

type messagesContainerHeaders struct {
	messagesContainerHeadersData

	pool   *messagesContainerHeadersPool
	isBusy bool
}

var (
	messageHeadersSize           = uint(binary.Size(messageHeadersData{}))
	messagesContainerHeadersSize = uint(binary.Size(messagesContainerHeadersData{}))
)

func (hdr *messageHeadersData) Reset() {
	hdr.Type = messageTypeUndefined
	hdr.Reserved0 = 0
	hdr.Length = 0
}

type messageHeadersPool struct {
	storage sync.Pool
}

func newMessageHeadersPool() *messageHeadersPool {
	pool := &messageHeadersPool{}
	pool.storage.New = func() interface{} {
		msg := &messageHeaders{
			pool: pool,
		}
		return msg
	}
	return pool
}

func (hdr *messageHeadersData) Set(msgType MessageType, payload []byte) {
	hdr.Type = msgType
	hdr.Length = messageLength(len(payload))
}

func (pool *messageHeadersPool) AcquireMessageHeaders() *messageHeaders {
	hdr := pool.storage.Get().(*messageHeaders)
	if hdr.isBusy {
		panic(`should not happened`)
	}
	hdr.isBusy = true
	return hdr
}

func (pool *messageHeadersPool) Put(hdr *messageHeaders) {
	if hdr == nil || !hdr.isBusy {
		panic(`should not happened`)
	}
	hdr.Reset()
	hdr.isBusy = false
	pool.storage.Put(hdr)
}

func (hdr *messageHeaders) Release() {
	hdr.pool.Put(hdr)
}

func (hdr *messageHeadersData) Read(b []byte) (int, error) {
	if uint(len(b)) < messageHeadersSize {
		return 0, newErrTooShort(messageHeadersSize, uint(len(b)))
	}
	hdr.Type = MessageType(b[0])
	hdr.Length = messageLength(binaryOrderType.Uint32(b[4:]))

	return int(messageHeadersSize), nil
}

func (hdr *messageHeadersData) Write(b []byte) (int, error) {
	if uint(len(b)) < messageHeadersSize {
		return 0, newErrTooShort(messageHeadersSize, uint(len(b)))
	}

	b[0] = uint8(hdr.Type)
	binaryOrderType.PutUint32(b[4:], uint32(hdr.Length))

	return int(messageHeadersSize), nil
}

func (containerHdr *messagesContainerHeadersData) SetNextPacketID(sess *Session) {
	containerHdr.PacketID.SetNextPacketID(sess)
}

func (containerHdr *messagesContainerHeadersData) calculatePoly1305Key(cipherKey []byte) (result [32]byte) {
	copy(result[:len(containerHdr.PacketID)], containerHdr.PacketID[:])
	copy(result[len(containerHdr.PacketID):], cipherKey)
	for idx := range result {
		result[idx] ^= poly1305KeyXORer[idx]
	}
	result = blake3.Sum256(result[:])
	return result
}

func (containerHdr *messagesContainerHeadersData) CalculateHeadersChecksumTo(cipherKey []byte, dst *[poly1305.TagSize]byte) {
	key := containerHdr.calculatePoly1305Key(cipherKey)
	poly1305.Sum(
		dst,
		unsafetools.BytesOf(containerHdr)[len(containerHdr.PacketID)+poly1305.TagSize*2:],
		&key,
	)
}

func (containerHdr *messagesContainerHeadersData) CalculateMessagesChecksumTo(cipherKey []byte, dst *[poly1305.TagSize]byte, messagesBytes []byte) {
	key := containerHdr.calculatePoly1305Key(cipherKey)
	poly1305.Sum(
		dst,
		messagesBytes,
		&key,
	)
}

func (containerHdr *messagesContainerHeadersData) Read(b []byte) (int, error) {
	if uint(len(b)) < messagesContainerHeadersSize {
		return 0, newErrTooShort(messagesContainerHeadersSize, uint(len(b)))
	}

	ivN, err := containerHdr.PacketID.Read(b)
	if err != nil {
		return 0, wrapError(err)
	}

	n, err := containerHdr.ReadAfterIV(b[len(containerHdr.PacketID):])
	if err != nil {
		return 0, err
	}
	return n + ivN, nil
}

func (containerHdr *messagesContainerHeadersData) ReadAfterIV(b []byte) (int, error) {
	copy(containerHdr.ContainerHeadersChecksum[:], b[:poly1305.TagSize])
	b = b[poly1305.TagSize:]
	copy(containerHdr.MessagesChecksum[:], b[:poly1305.TagSize])
	b = b[poly1305.TagSize:]
	containerHdr.Length = messageLength(binaryOrderType.Uint32(b))
	b = b[4:]
	containerHdr.messagesContainerFlags = messagesContainerFlags(b[0])
	b = b[1:]
	containerHdr.Reserved0 = b[0]
	b = b[1:]
	containerHdr.Reserved1 = binaryOrderType.Uint16(b)
	b = b[2:]

	return int(messagesContainerHeadersSize) - len(containerHdr.PacketID), nil
}

func (containerHdr *messagesContainerHeadersData) Write(b []byte) (int, error) {
	if uint(len(b)) < messagesContainerHeadersSize {
		return 0, newErrTooShort(messagesContainerHeadersSize, uint(len(b)))
	}

	_, err := containerHdr.PacketID.Write(b)
	if err != nil {
		return 0, wrapError(err)
	}
	b = b[len(containerHdr.PacketID):]
	copy(b, containerHdr.ContainerHeadersChecksum[:])
	b = b[poly1305.TagSize:]
	copy(b, containerHdr.MessagesChecksum[:])
	b = b[poly1305.TagSize:]
	binaryOrderType.PutUint32(b, uint32(containerHdr.Length))
	b = b[4:]
	b[0] = uint8(containerHdr.messagesContainerFlags)
	b = b[1:]
	b[0] = containerHdr.Reserved0
	b = b[1:]
	binaryOrderType.PutUint16(b, containerHdr.Reserved1)
	b = b[2:]

	return int(messagesContainerHeadersSize), nil
}

var messagesContainerHeadersSizeBufPool = sync.Pool{New: func() interface{} {
	return make([]byte, messagesContainerHeadersSize)
}}

func (containerHdr *messagesContainerHeadersData) WriteTo(w io.Writer) (int64, error) {
	buf := messagesContainerHeadersSizeBufPool.Get().([]byte)
	defer messagesContainerHeadersSizeBufPool.Put(buf)

	n0, err := containerHdr.Write(buf)
	if err != nil {
		return int64(n0), xerrors.Errorf(
			"unable to write the headers' data to a buffer: %w", err,
		)
	}

	n1, err := w.Write(buf)
	if err != nil {
		return int64(n1), xerrors.Errorf(
			"unable to write headers' data from a buffer to a writer: %w", err,
		)
	}
	return int64(n0 + n1), nil
}

type messagesContainerHeadersPool struct {
	storage sync.Pool
}

func newMessagesContainerHeadersPool() *messagesContainerHeadersPool {
	pool := &messagesContainerHeadersPool{}
	pool.storage.New = func() interface{} {
		containerHdr := &messagesContainerHeaders{
			pool: pool,
		}
		return containerHdr
	}
	return pool
}

func (pool *messagesContainerHeadersPool) AcquireMessagesContainerHeaders(sess *Session) *messagesContainerHeaders {
	containerHdr := pool.storage.Get().(*messagesContainerHeaders)
	if containerHdr.isBusy {
		panic(`should not happened`)
	}
	containerHdr.isBusy = true
	containerHdr.SetNextPacketID(sess)
	return containerHdr
}

func (pool *messagesContainerHeadersPool) Put(containerHdr *messagesContainerHeaders) {
	if containerHdr == nil || !containerHdr.isBusy {
		panic(`should not happened`)
	}
	containerHdr.Reset()
	containerHdr.isBusy = false
	pool.storage.Put(containerHdr)
}

func (containerHdr *messagesContainerHeadersData) Set(cipherKey []byte, messagesBytes []byte) error {
	containerHdr.SetIsEncrypted(cipherKey != nil)
	containerHdr.Length = messageLength(len(messagesBytes))
	containerHdr.CalculateHeadersChecksumTo(cipherKey, &containerHdr.ContainerHeadersChecksum)
	containerHdr.CalculateMessagesChecksumTo(cipherKey, &containerHdr.MessagesChecksum, messagesBytes)
	return nil
}

func (containerHdr *messagesContainerHeadersData) Reset() {
	containerHdr.Length = 0
	slice.SetZeros(containerHdr.ContainerHeadersChecksum[:])
	slice.SetZeros(containerHdr.MessagesChecksum[:])
	containerHdr.messagesContainerFlags = 0
	containerHdr.Reserved0 = 0
	containerHdr.Reserved1 = 0
}

func (containerHdr *messagesContainerHeaders) Release() {
	containerHdr.pool.Put(containerHdr)
}
