package secureio

import (
	"crypto/aes"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xaionaro-go/slice"
	"github.com/xaionaro-go/unsafetools"
	"golang.org/x/crypto/poly1305"
	"lukechampine.com/blake3"
)

const (
	maxPossiblePacketSize = 1<<16 - 256
)

const (
	ivSize = 8
)

var (
	maxPayloadSize uint32
)

func init() {
	SetMaxPayloadSize(uint32(maxPossiblePacketSize - messagesContainerHeadersSize - messageHeadersSize))
}

func SetMaxPayloadSize(newSize uint32) {
	newSize &= ^(uint32(aes.BlockSize) - 1)
	atomic.StoreUint32(&maxPayloadSize, newSize)
}

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
	MessageType_dataPacketType8
	MessageType_dataPacketType9
	MessageType_dataPacketType10
	MessageType_dataPacketType11
	MessageType_dataPacketType12
	MessageType_dataPacketType13
	MessageType_dataPacketType14
	MessageType_dataPacketType15

	MessageTypeMax
)

func (t MessageType) String() string {
	switch t {
	case MessageType_undefined:
		return `undefined`
	case MessageType_keyExchange:
		return `key_exchange`
	case MessageType_dataPacketType0:
		return `datatype0`
	case MessageType_dataPacketType1:
		return `datatype1`
	case MessageType_dataPacketType2:
		return `datatype2`
	case MessageType_dataPacketType3:
		return `datatype3`
	case MessageType_dataPacketType4:
		return `datatype4`
	case MessageType_dataPacketType5:
		return `datatype5`
	case MessageType_dataPacketType6:
		return `datatype6`
	case MessageType_dataPacketType7:
		return `datatype7`
	case MessageType_dataPacketType8:
		return `datatype8`
	case MessageType_dataPacketType9:
		return `datatype9`
	case MessageType_dataPacketType10:
		return `datatype10`
	case MessageType_dataPacketType11:
		return `datatype11`
	case MessageType_dataPacketType12:
		return `datatype12`
	case MessageType_dataPacketType13:
		return `datatype13`
	case MessageType_dataPacketType14:
		return `datatype14`
	case MessageType_dataPacketType15:
		return `datatype15`
	}
	return `unknown`
}

type MessageLength uint32

type messageHeadersData struct {
	Type      MessageType
	Reserved0 uint8
	Reserved1 uint16
	Length    MessageLength
}

type messageHeaders struct {
	messageHeadersData

	pool   *messageHeadersPool
	isBusy bool
}

type MessagesContainerFlags uint8

const (
	MessagesContainerFlagsIsEncrypted = MessagesContainerFlags(1 << iota)
)

func (flags MessagesContainerFlags) IsEncrypted() bool {
	return flags&MessagesContainerFlagsIsEncrypted != 0
}
func (flags *MessagesContainerFlags) SetIsEncrypted(newValue bool) {
	if newValue {
		*flags |= MessagesContainerFlagsIsEncrypted
	} else {
		*flags &= ^MessagesContainerFlagsIsEncrypted
	}
}

type Time [ivSize]byte

func (t *Time) Time() time.Time {
	nanoseconds := binaryOrderType.Uint64(t[:])
	return time.Unix(0, int64(nanoseconds))
}
func (t *Time) String() string {
	return t.Time().String()
}
func (t *Time) Set(v time.Time) {
	nanoseconds := uint64(v.UnixNano())
	binaryOrderType.PutUint64((*t)[:], nanoseconds)
}
func (t *Time) Read(b []byte) (int, error) {
	if len(b) < ivSize {
		return 0, newErrTooShort(ivSize, uint(len(b)))
	}
	copy((*t)[:], b)
	return ivSize, nil
}
func (t *Time) Write(b []byte) (int, error) {
	if len(b) < ivSize {
		return 0, newErrTooShort(ivSize, uint(len(b)))
	}
	copy(b, (*t)[:])
	return ivSize, nil
}

type messagesContainerHeadersData struct {
	Time Time // Should be the first. It is used to decrypt other values!

	ContainerHeadersChecksum [poly1305.TagSize]byte
	MessagesChecksum         [poly1305.TagSize]byte
	CreatedAt                uint64
	Length                   MessageLength
	MessagesContainerFlags
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
	hdr.Type = MessageType_undefined
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
	hdr.Length = MessageLength(len(payload))
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
	hdr.Length = MessageLength(binaryOrderType.Uint32(b[4:]))

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

func (containerHdr *messagesContainerHeadersData) UpdateTime() {
	containerHdr.Time.Set(time.Now())
}

func (containerHdr *messagesContainerHeadersData) calculatePoly1305Key(cipherKey []byte) (result [32]byte) {
	copy(result[:ivSize], containerHdr.Time[:])
	copy(result[ivSize:], cipherKey)
	result = blake3.Sum256(result[:])
	return result
}

func (containerHdr *messagesContainerHeadersData) CalculateHeadersChecksumTo(cipherKey []byte, dst *[poly1305.TagSize]byte) {
	key := containerHdr.calculatePoly1305Key(cipherKey)
	poly1305.Sum(
		dst,
		unsafetools.BytesOf(containerHdr)[ivSize+poly1305.TagSize*2:],
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

	ivN, err := containerHdr.Time.Read(b)
	if err != nil {
		return 0, wrapError(err)
	}

	n, err := containerHdr.ReadAfterIV(b[ivSize:])
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
	containerHdr.Length = MessageLength(binaryOrderType.Uint32(b))
	b = b[4:]
	containerHdr.MessagesContainerFlags = MessagesContainerFlags(b[0])
	b = b[1:]
	containerHdr.Reserved0 = b[0]
	b = b[1:]
	containerHdr.Reserved1 = binaryOrderType.Uint16(b)
	b = b[2:]

	return int(messagesContainerHeadersSize) - ivSize, nil
}

func (containerHdr *messagesContainerHeadersData) Write(b []byte) (int, error) {
	if uint(len(b)) < messagesContainerHeadersSize {
		return 0, newErrTooShort(messagesContainerHeadersSize, uint(len(b)))
	}

	_, err := containerHdr.Time.Write(b)
	if err != nil {
		return 0, wrapError(err)
	}
	b = b[ivSize:]
	copy(b, containerHdr.ContainerHeadersChecksum[:])
	b = b[poly1305.TagSize:]
	copy(b, containerHdr.MessagesChecksum[:])
	b = b[poly1305.TagSize:]
	binaryOrderType.PutUint32(b, uint32(containerHdr.Length))
	b = b[4:]
	b[0] = uint8(containerHdr.MessagesContainerFlags)
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

func (containerHdr *messagesContainerHeadersData) WriteTo(w io.Writer) (int, error) {
	buf := messagesContainerHeadersSizeBufPool.Get().([]byte)
	defer messagesContainerHeadersSizeBufPool.Put(buf)

	n0, err := containerHdr.Write(buf)
	if err != nil {
		return n0, wrapErrorf(
			"unable to write the headers' data to a buffer: %w", err,
		)
	}

	n1, err := w.Write(buf)
	if err != nil {
		return n1, wrapErrorf(
			"unable to write headers' data from a buffer to a writer: %w", err,
		)
	}
	return n0 + n1, nil
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

func (pool *messagesContainerHeadersPool) AcquireMessagesContainerHeaders() *messagesContainerHeaders {
	containerHdr := pool.storage.Get().(*messagesContainerHeaders)
	if containerHdr.isBusy {
		panic(`should not happened`)
	}
	containerHdr.isBusy = true
	containerHdr.UpdateTime()
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
	containerHdr.Length = MessageLength(len(messagesBytes))
	containerHdr.CalculateHeadersChecksumTo(cipherKey, &containerHdr.ContainerHeadersChecksum)
	containerHdr.CalculateMessagesChecksumTo(cipherKey, &containerHdr.MessagesChecksum, messagesBytes)
	return nil
}

func (containerHdr *messagesContainerHeadersData) Reset() {
	containerHdr.Length = 0
	slice.SetZeros(containerHdr.ContainerHeadersChecksum[:])
	slice.SetZeros(containerHdr.MessagesChecksum[:])
	containerHdr.MessagesContainerFlags = 0
	containerHdr.Reserved0 = 0
	containerHdr.Reserved1 = 0
}

func (containerHdr *messagesContainerHeaders) Release() {
	containerHdr.pool.Put(containerHdr)
}
