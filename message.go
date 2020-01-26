package secureio

import (
	"crypto/aes"
	"encoding/binary"
	"hash"
	"hash/crc64"
	"io"
	"sync"
	"sync/atomic"
)

const (
	maxPossiblePacketSize = 1<<16 - 256
)

const (
	ivSize = aes.BlockSize
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

var (
	// NoncePRNG is the PRNG used for NONCE-s which is not required
	// to be cryptographically strong, but required to do not repeat
	// as much as possible.
	NonceRand = newXorShiftPRNG()
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

type messagesContainerHeadersData struct {
	IV [ivSize]byte // Should be the first. It is used to decrypt other values!

	ContainerHeadersChecksum uint64
	MessagesChecksum         uint64
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

var (
	crc64Pool = sync.Pool{
		New: func() interface{} {
			return crc64.New(crc64.MakeTable(crc64.ECMA))
		},
	}
)

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

func (containerHdr *messagesContainerHeadersData) RandomizeIV() {
	_, _ = NonceRand.ReadUint64Xorshift(containerHdr.IV[:])
}

func (containerHdr *messagesContainerHeadersData) CalculateChecksum(messagesBytes []byte) error {
	checksumer := crc64Pool.Get().(hash.Hash64)
	err := func() (err error) {
		containerHdr.ContainerHeadersChecksum = 0
		containerHdr.MessagesChecksum = 0
		_, err = containerHdr.WriteTo(checksumer)
		if err != nil {
			return wrapErrorf("unable to calculate checksum of a header: %w", err)
		}

		containerHdr.ContainerHeadersChecksum = checksumer.Sum64()

		n, err := checksumer.Write(messagesBytes)
		if n != len(messagesBytes) && err == nil {
			err = newErrPartialWrite()
		}
		if err != nil {
			err = wrapErrorf("unable to calculate checksum of a payload: %w", err)
		}

		containerHdr.MessagesChecksum = checksumer.Sum64()
		return
	}()
	checksumer.Reset()
	crc64Pool.Put(checksumer)

	if err != nil {
		return wrapErrorf("unable to calculate checksum: %w", err)
	}

	return nil
}

func (containerHdr *messagesContainerHeadersData) Read(b []byte) (int, error) {
	if uint(len(b)) < messagesContainerHeadersSize {
		return 0, newErrTooShort(messagesContainerHeadersSize, uint(len(b)))
	}

	copy(containerHdr.IV[:], b)

	n, err := containerHdr.ReadAfterIV(b[ivSize:])
	if err != nil {
		return 0, err
	}
	return n + ivSize, nil
}

func (containerHdr *messagesContainerHeadersData) ReadAfterIV(b []byte) (int, error) {
	containerHdr.ContainerHeadersChecksum = binaryOrderType.Uint64(b)
	containerHdr.MessagesChecksum = binaryOrderType.Uint64(b[8:])
	containerHdr.Length = MessageLength(binaryOrderType.Uint32(b[16:]))
	containerHdr.MessagesContainerFlags = MessagesContainerFlags(b[20])
	containerHdr.Reserved0 = b[21]
	containerHdr.Reserved1 = binaryOrderType.Uint16(b[22:])

	return int(messagesContainerHeadersSize) - ivSize, nil
}

func (containerHdr *messagesContainerHeadersData) Write(b []byte) (int, error) {
	if uint(len(b)) < messagesContainerHeadersSize {
		return 0, newErrTooShort(messagesContainerHeadersSize, uint(len(b)))
	}

	copy(b, containerHdr.IV[:])
	binaryOrderType.PutUint64(b[16:], uint64(containerHdr.ContainerHeadersChecksum))
	binaryOrderType.PutUint64(b[24:], uint64(containerHdr.MessagesChecksum))
	binaryOrderType.PutUint32(b[32:], uint32(containerHdr.Length))
	b[36] = uint8(containerHdr.MessagesContainerFlags)
	b[37] = containerHdr.Reserved0
	binaryOrderType.PutUint16(b[38:], containerHdr.Reserved1)

	return int(messagesContainerHeadersSize), nil
}

func (containerHdr *messagesContainerHeadersData) WriteTo(w io.Writer) (int, error) {
	buf := make([]byte, messagesContainerHeadersSize)

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
		containerHdr.RandomizeIV()
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

func (containerHdr *messagesContainerHeadersData) Set(isEncrypted bool, messagesBytes []byte) error {
	containerHdr.SetIsEncrypted(isEncrypted)
	containerHdr.Length = MessageLength(len(messagesBytes))
	err := containerHdr.CalculateChecksum(messagesBytes)
	if err != nil {
		return wrapError(err)
	}
	return nil
}

func (containerHdr *messagesContainerHeadersData) Reset() {
	containerHdr.Length = 0
	containerHdr.ContainerHeadersChecksum = 0
	containerHdr.MessagesChecksum = 0
	containerHdr.MessagesContainerFlags = 0
	containerHdr.Reserved0 = 0
	containerHdr.Reserved1 = 0
	containerHdr.RandomizeIV()
}

func (containerHdr *messagesContainerHeaders) Release() {
	containerHdr.pool.Put(containerHdr)
}
