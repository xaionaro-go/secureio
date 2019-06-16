package secureio

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	e "errors"
	"hash/crc32"
	"io"
	"runtime"
	"sync"

	"github.com/xaionaro-go/errors"
)

const (
	updateKeyEveryNBytes = 1000000
	messageQueueLength   = 1024
)

var (
	maxPacketSize = roundSize(maxPayloadSize+int(messageHeadersSize), aes.BlockSize)
)

func roundSize(size, blockSize int) int {
	return (size + (blockSize - 1)) & ^(blockSize - 1)
}

var (
	ErrTooBig = e.New("message is too big")
	//ErrReadWhileSessionIsClosed  = e.New("a read attempt on a closed session")
	//ErrWriteWhileSessionIsClosed = e.New("a write attempt on a closed session")
	ErrAlreadyClosed   = e.New("already closed")
	ErrInvalidChecksum = e.New("invalid checksum (or invalid encryption key)")
	ErrCannotDecrypt   = e.New("cannot decrypt")
)

type Checksumer interface {
	io.Writer

	Sum32() uint32
	Reset()
}

type ReadItem struct {
	Data []byte
}

func (it *ReadItem) Release() {
	it.Data = it.Data[:0]
	readItemPool.Put(it)
}

type Session struct {
	locker sync.RWMutex

	state          SessionState
	identity       *Identity
	remoteIdentity *Identity
	keyExchanger   *keyExchanger
	backend        io.ReadWriteCloser
	messenger      [MessageTypeMax]*Messenger
	ReadChan       [MessageTypeMax]chan *ReadItem
	closeChan      chan struct{}
	cipher         cipher.Block
	previousCipher cipher.Block
	logger         Logger
	writeDeferChan chan *writeItem
}

func (sess *Session) WaitForState(states ...SessionState) SessionState {
	return sess.state.WaitFor(states...)
}

func (sess *Session) GetState() SessionState {
	return sess.state.Get()
}

func (sess *Session) setState(state SessionState, cancelOnStates ...SessionState) (oldState SessionState) {
	sess.logger.Debugf("setState: %v %v", state, cancelOnStates)
	return sess.state.Set(state, cancelOnStates...)
}

func panicIf(err error) {
	if err != nil {
		panic(err)
	}
}

var (
	readItemPool = sync.Pool{
		New: func() interface{} {
			return &ReadItem{
				Data: make([]byte, 0, maxPacketSize),
			}
		},
	}
)

func newSession(identity, remoteIdentity *Identity, backend io.ReadWriteCloser, logger Logger) *Session {
	sess := &Session{
		identity:       identity,
		remoteIdentity: remoteIdentity,
		closeChan:      make(chan struct{}),
		state:          SessionState_new,
		backend:        backend,
		logger:         logger,
		writeDeferChan: make(chan *writeItem, 1024),
	}

	for i := 0; i < MessageTypeMax; i++ {
		sess.ReadChan[i] = make(chan *ReadItem, messageQueueLength)
	}

	panicIf(sess.init())
	return sess
}

func (sess *Session) init() error {
	sess.startKeyExchange()
	sess.startReader()
	return nil
}

func (sess *Session) startReader() {
	go sess.readerLoop()
}

func (sess *Session) readerLoop() {
	var inputBuffer = make([]byte, maxPacketSize)
	var decryptedBuffer Buffer
	decryptedBuffer.Grow(maxPacketSize)
	for {
		select {
		case <-sess.closeChan:
			close(sess.closeChan)
			return
		default:
		}
		item := readItemPool.Get().(*ReadItem)
		sess.logger.Debugf("n, err := sess.backend.Read(inputBuffer)")
		n, err := sess.backend.Read(inputBuffer)
		sess.logger.Debugf("/n, err := sess.backend.Read(inputBuffer): %v %v", n, err)
		if err != nil {
			_ = sess.Close()
			sess.logger.Error(sess, errors.Wrap(err))
			continue
		}

		hdr, payload, err := sess.decrypt(&decryptedBuffer, inputBuffer[:n])
		sess.logger.Debugf("%v %v %v", hdr, payload, err)
		if err != nil {
			sess.logger.Infof("cannot decrypt: %v", errors.Wrap(err))
			continue
		}

		item.Data = item.Data[0:hdr.Length]
		copy(item.Data, payload)
		if sess.messenger[hdr.Type] != nil {
			if err := sess.messenger[hdr.Type].Handle(payload); err != nil {
				_ = sess.Close()
				sess.logger.Error(sess, errors.Wrap(err))
				continue
			}
		} else {
			sess.ReadChan[hdr.Type] <- item
		}
		hdr.Release()
	}
}

func (sess *Session) decrypt(decrypted *Buffer, encrypted []byte) (*messageHeaders, []byte, error) {
	hdr := newMessageHeaders()

	decrypted.Reset()
	decrypted.Grow(len(encrypted))
	if sess.cipher == nil {
		copy(decrypted.Bytes, encrypted)
	} else {
		sess.cipher.Decrypt(decrypted.Bytes, encrypted)
	}

	sess.logger.Debugf("DDD %v %v %v", decrypted.Bytes, encrypted, decrypted.Len())

	err := binary.Read(decrypted, binaryOrderType, hdr)
	sess.logger.Debugf("BR %v %v %v %v %v", err, hdr, decrypted.Len(), decrypted.Cap(), decrypted.Offset)
	if err != nil {
		hdr.Release()
		return nil, nil, errors.Wrap(err)
	}

	if err := sess.checkChecksum(hdr, decrypted); err != nil {
		decrypted.Reset()
		decrypted.Grow(len(encrypted))
		if sess.previousCipher == nil {
			copy(decrypted.Bytes, encrypted)
		} else {
			sess.previousCipher.Decrypt(decrypted.Bytes, encrypted)
		}

		err := binary.Read(decrypted, binaryOrderType, hdr)
		if err != nil {
			hdr.Release()
			return nil, nil, errors.Wrap(err)
		}

		if err := sess.checkChecksum(hdr, decrypted); err != nil {
			hdr.Release()
			return nil, nil, errors.Wrap(ErrCannotDecrypt, err)
		}
	}

	return hdr, decrypted.Bytes[decrypted.Offset:], nil
}

func (sess *Session) checkChecksum(hdr *messageHeaders, decrypted *Buffer) error {
	checksum := hdr.Checksum
	hdr.Checksum = 0

	checksumer := crc32.NewIEEE()
	err := binary.Write(checksumer, binaryOrderType, hdr)
	if err != nil {
		return errors.Wrap(err)
	}

	_, err = checksumer.Write(decrypted.Bytes[decrypted.Offset : int(decrypted.Offset)+int(hdr.Length)])
	if err != nil {
		return errors.Wrap(err)
	}

	if checksumer.Sum32() != checksum {
		return errors.Wrap(ErrInvalidChecksum, checksumer.Sum32(), checksum)
	}

	return nil
}

func (sess *Session) isAlreadyLockedByMe() bool {
	pc := make([]uintptr, 8)
	l := runtime.Callers(1, pc)
	if l < 2 {
		panic("l < 2")
	}
	lockDoPtr := pc[0]
	for i := 1; i < l; i++ {
		if pc[i] == lockDoPtr {
			return true
		}
	}
	return false
}

func (sess *Session) LockDo(fn func()) {
	if !sess.isAlreadyLockedByMe() {
		sess.locker.Lock()
		defer sess.locker.Unlock()
	}
	fn()
}

func (sess *Session) NewMessenger(msgType MessageType) *Messenger {
	messenger := newMessenger(msgType, sess)
	sess.setMessenger(msgType, messenger)
	return messenger
}

type writeItem struct {
	MsgType MessageType
	Payload []byte
}

var (
	writeItemPool = sync.Pool{
		New: func() interface{} {
			return &writeItem{
				Payload: make([]byte, maxPacketSize),
			}
		},
	}
)

func newWriteItem() *writeItem {
	return writeItemPool.Get().(*writeItem)
}

func (it *writeItem) Release() {
	it.Reset()
	writeItemPool.Put(it)
}

func (it *writeItem) Reset() {
}

func (sess *Session) sendDeferred() {
	sess.logger.Debugf("sendDeferred")
	for {
		select {
		case item := <-sess.writeDeferChan:
			_, err := sess.WriteMessage(item.MsgType, item.Payload)
			if err != nil {
				sess.logger.Error(sess, err)
			}
		default:
			return
		}
	}
}

func (sess *Session) WriteMessage(msgType MessageType, payload []byte) (int, error) {
	if len(payload) > maxPayloadSize {
		return -1, errors.Wrap(ErrTooBig)
	}

	if msgType != MessageType_keyExchange {
		shouldBreak := false
		sess.LockDo(func() {
			if sess.cipher == nil {
				item := newWriteItem()
				item.MsgType = msgType
				item.Payload = item.Payload[:len(payload)]
				copy(item.Payload, payload)
				sess.writeDeferChan <- item
				shouldBreak = true
				return
			}
		})
		if shouldBreak {
			return len(payload), nil
		}
	}

	msg := newMessageHeaders()
	defer msg.Release()

	msg.Type = msgType
	msg.Length = uint16(len(payload))
	msg.Checksum = 0

	checksumer := crc32.NewIEEE()
	err := binary.Write(checksumer, binaryOrderType, msg)
	if err != nil {
		return -1, errors.Wrap(err)
	}
	n, err := checksumer.Write(payload)
	if n != len(payload) && err == nil {
		err = ErrPartialWrite
	}
	if err != nil {
		return n, errors.Wrap(err)
	}

	msg.Checksum = checksumer.Sum32()

	plain := newBytesBuffer()

	err = binary.Write(plain, binaryOrderType, msg)
	if err != nil {
		return -1, errors.Wrap(err)
	}
	n, err = plain.Write(payload)
	if n != len(payload) && err == nil {
		err = errors.Wrap(ErrTooBig)
	}
	if err == nil {
		n = len(payload)
	}

	if sess.cipher == nil {
		n, err = sess.backend.Write(plain.Bytes())
	} else {
		encrypted := newBytesBuffer()
		size := roundSize(plain.Len(), aes.BlockSize)
		plain.Grow(size)
		plainBytes := plain.Bytes()[:size]

		encryptedBytes := encrypted.Bytes()[:size]
		sess.cipher.Encrypt(encryptedBytes, plainBytes)
		n, err = sess.backend.Write(encryptedBytes)
		encrypted.Release()
	}
	plain.Release()
	return n, errors.Wrap(err)
}

func (sess *Session) startKeyExchange() {
	switch sess.setState(SessionState_keyExchanging, SessionState_closing, SessionState_closed) {
	case SessionState_keyExchanging, SessionState_closing, SessionState_closed:
		return
	}

	sess.keyExchanger = newKeyExchanger(sess.identity, sess.remoteIdentity, sess.NewMessenger(MessageType_keyExchange), func(secret []byte) {
		// ok
		sess.logger.Debugf("got key: %v", secret)
		sess.setSecret(secret)
		sess.setState(SessionState_established)
		sess.sendDeferred()
	}, func(err error) {
		// got error
		_ = sess.Close()
		sess.logger.Error(sess, errors.Wrap(err))
	})
}

func (sess *Session) setMessenger(msgType MessageType, messenger *Messenger) {
	sess.LockDo(func() {
		if sess.messenger[msgType] != nil {
			sess.messenger[msgType].Close()
		}
		sess.messenger[msgType] = messenger
	})
}

func (sess *Session) setSecret(newSecret []byte) {
	sess.LockDo(func() {
		sess.previousCipher = sess.cipher
		var err error
		sess.cipher, err = aes.NewCipher(newSecret[:aes.BlockSize*2]) // AES-256
		if err != nil {
			panic(err)
		}
	})
}

func (sess *Session) read(p []byte) (int, error) {
	item := <-sess.ReadChan[MessageType_dataPacketType0]
	if len(p) < len(item.Data) {
		return -1, errors.Wrap(ErrTooBig)
	}
	copy(p, item.Data)
	n := len(item.Data)
	item.Release()
	return n, nil
}

func (sess *Session) Read(p []byte) (int, error) {
	return sess.read(p)
}

type bytesBuffer struct {
	bytes.Buffer
}

var (
	bytesBufferPool = sync.Pool{
		New: func() interface{} {
			return &bytesBuffer{}
		},
	}
)

func newBytesBuffer() *bytesBuffer {
	buf := bytesBufferPool.Get().(*bytesBuffer)
	buf.Grow(maxPacketSize)
	return buf
}

func (buf *bytesBuffer) Release() {
	buf.Reset()
	bytesBufferPool.Put(buf)
}

func (sess *Session) write(raw []byte) (int, error) {
	if len(raw) > maxPayloadSize {
		return -1, errors.Wrap(ErrTooBig)
	}
	return sess.WriteMessage(MessageType_dataPacketType0, raw)
}

func (sess *Session) Write(p []byte) (int, error) {
	return sess.write(p)
}

func (sess *Session) Close() error {
	switch sess.setState(SessionState_closing) {
	case SessionState_closed, SessionState_closing:
		return errors.Wrap(ErrAlreadyClosed)
	}
	sess.closeChan <- struct{}{}
	err := sess.backend.Close()
	sess.setState(SessionState_closed)
	return err
}
