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
	cipherBlockSize      = aes.BlockSize
	cannotDecryptLimit   = 5
)

var (
	ErrUnencrypted = e.New(`unencrypted message`)
)

var (
	maxPacketSize = roundSize(maxPayloadSize+int(messageHeadersSize), cipherBlockSize)
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
	ErrInvalidLength   = e.New("invalid length")
	ErrEmptyInput      = e.New("empty input")
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
	oldState = sess.state.Set(state, cancelOnStates...)
	sess.logger.Debugf("setState: %v %v %v", state, cancelOnStates, oldState)
	return
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
	cannotDecryptCount := 0
	var inputBuffer = make([]byte, maxPacketSize)
	var decryptedBuffer Buffer
	decryptedBuffer.Grow(maxPacketSize)
	for {
		select {
		case <-sess.closeChan:
			close(sess.closeChan)
			sess.setState(SessionState_closed)
			for _, messenger := range sess.messenger {
				if messenger == nil {
					continue
				}
				_ = messenger.Close()
			}
			sess.logger.Debugf("secureio session closed")
			return
		default:
		}
		item := readItemPool.Get().(*ReadItem)
		sess.logger.Debugf("n, err := sess.backend.Read(inputBuffer)")
		n, err := sess.backend.Read(inputBuffer)
		sess.logger.Debugf("/n, err := sess.backend.Read(inputBuffer): %v %v", n, err)
		if err != nil {
			sess.logger.Error(sess, errors.Wrap(err))
			continue
		}
		if n == 0 {
			continue
		}

		hdr, payload, err := sess.decrypt(&decryptedBuffer, inputBuffer[:n])
		sess.logger.Debugf("%v %v %v", hdr, payload, err)
		if err != nil && (err != ErrUnencrypted || hdr.Type != MessageType_keyExchange) {
			err = errors.Wrap(err)
			sess.logger.Infof("cannot decrypt: %v", err)
			cannotDecryptCount++
			if cannotDecryptCount > cannotDecryptLimit {
				sess.logger.Error(sess, err)
			}
			continue
		}

		item.Data = item.Data[0:hdr.Length]
		copy(item.Data, payload)
		if sess.messenger[hdr.Type] != nil {
			if err := sess.messenger[hdr.Type].Handle(payload); err != nil {
				sess.logger.Error(sess, errors.Wrap(err))
				continue
			}
		} else {
			sess.ReadChan[hdr.Type] <- item
		}
		hdr.Release()
	}
}

func cipherDo(convertFunc func(dst, src []byte), dst, src []byte) {
	for i := 0; i < len(src); i += cipherBlockSize {
		convertFunc(dst[i:i+cipherBlockSize], src[i:i+cipherBlockSize])
	}
}

func (sess *Session) decrypt(decrypted *Buffer, encrypted []byte) (*messageHeaders, []byte, error) {
	hdr := newMessageHeaders()

	decrypted.Reset()
	decrypted.Grow(len(encrypted))
	if sess.cipher == nil {
		copy(decrypted.Bytes, encrypted)
	} else {
		cipherDo(sess.cipher.Decrypt, decrypted.Bytes, encrypted)
	}

	sess.logger.Debugf("decrypting: %v %v %v", decrypted.Bytes, encrypted, decrypted.Len())

	err := binary.Read(decrypted, binaryOrderType, hdr)
	sess.logger.Debugf("decrypted headers: %v %v %v %v %v", err, hdr, decrypted.Len(), decrypted.Cap(), decrypted.Offset)
	if err != nil {
		hdr.Release()
		return nil, nil, errors.Wrap(err)
	}

	if len(decrypted.Bytes) < decrypted.Offset {
		return nil, nil, errors.Wrap(ErrEmptyInput, len(decrypted.Bytes), decrypted.Offset)
	}

	err = sess.checkChecksum(hdr, decrypted)
	if err == nil {
		return hdr, decrypted.Bytes[decrypted.Offset:], nil
	}

	var err2 error
	if sess.previousCipher != nil {
		decrypted.Reset()
		decrypted.Grow(len(encrypted))

		cipherDo(sess.previousCipher.Decrypt, decrypted.Bytes, encrypted)

		if err2 = binary.Read(decrypted, binaryOrderType, hdr); err2 != nil {
			hdr.Release()
			return nil, nil, errors.Wrap(err, err2)
		}

		if err2 = sess.checkChecksum(hdr, decrypted); err2 == nil {
			return hdr, decrypted.Bytes[decrypted.Offset:], nil
		}
	}

	decrypted.Reset()
	decrypted.Grow(len(encrypted))
	copy(decrypted.Bytes, encrypted)

	err3 := binary.Read(decrypted, binaryOrderType, hdr)
	if err3 != nil {
		hdr.Release()
		return nil, nil, errors.Wrap(err, err2, err3)
	}

	err3 = sess.checkChecksum(hdr, decrypted)
	if err3 == nil {
		return hdr, decrypted.Bytes[decrypted.Offset:], ErrUnencrypted
	}

	hdr.Release()
	return nil, nil, errors.Wrap(ErrCannotDecrypt, err, err2, err3)
}

func (sess *Session) checkChecksum(hdr *messageHeaders, decrypted *Buffer) error {
	checksum := hdr.Checksum
	hdr.Checksum = 0

	checksumer := crc32.NewIEEE()
	err := binary.Write(checksumer, binaryOrderType, hdr)
	if err != nil {
		return errors.Wrap(err, hdr)
	}

	if int(decrypted.Offset)+int(hdr.Length) > len(decrypted.Bytes) {
		return errors.Wrap(ErrInvalidLength, hdr, decrypted.Offset, hdr.Length, len(decrypted.Bytes))
	}

	_, err = checksumer.Write(decrypted.Bytes[decrypted.Offset : int(decrypted.Offset)+int(hdr.Length)])
	if err != nil {
		return errors.Wrap(err, hdr, decrypted.Offset, hdr.Length, len(decrypted.Bytes))
	}

	if checksumer.Sum32() != checksum {
		return errors.Wrap(ErrInvalidChecksum, checksumer.Sum32(), checksum, hdr, decrypted.Offset, hdr.Length, len(decrypted.Bytes))
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
			if sess.cipher != nil {
				return
			}
			item := newWriteItem()
			item.MsgType = msgType
			item.Payload = item.Payload[:len(payload)]
			copy(item.Payload, payload)
			sess.writeDeferChan <- item
			shouldBreak = true
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

	switch sess.GetState() {
	case SessionState_closed, SessionState_closing:
		return 0, errors.Wrap(ErrAlreadyClosed)
	}

	sess.logger.Debugf("sess.cipher == nil: %v", sess.cipher == nil)
	if sess.cipher == nil || msg.Type == MessageType_keyExchange {
		n, err = sess.backend.Write(plain.Bytes())
	} else {
		encrypted := newBytesBuffer()
		size := roundSize(plain.Len(), cipherBlockSize)
		plain.Grow(size)
		plainBytes := plain.Bytes()[:size]

		encryptedBytes := encrypted.Bytes()[:size]
		cipherDo(sess.cipher.Encrypt, encryptedBytes, plainBytes)
		sess.logger.Debugf("encrypted == %v; plain == %v", encryptedBytes, plainBytes)
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
		sess.setState(SessionState_established, SessionState_keyExchanging)
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
			err := errors.Wrap(sess.messenger[msgType].Close())
			if err != nil {
				sess.logger.Error(sess, err)
			}
		}
		sess.messenger[msgType] = messenger
	})
}

func (sess *Session) setSecret(newSecret []byte) {
	sess.LockDo(func() {
		sess.previousCipher = sess.cipher
		var err error
		key := newSecret[:cipherBlockSize]
		sess.cipher, err = aes.NewCipher(key)
		sess.logger.Debugf("new cipher with key: %v", key)
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
	go func() {
		sess.closeChan <- struct{}{}
		err := errors.Wrap(sess.backend.Close())
		if err != nil {
			sess.logger.Error(sess, err)
		}
	}()
	return nil
}
