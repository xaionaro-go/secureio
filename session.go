package secureio

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	e "errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/xaionaro-go/errors"
)

const (
	DefaultErrorOnSequentialDecryptFailsCount = 3
)

const (
	updateKeyEveryNBytes = 1000000
	messageQueueLength   = 1024
	cipherBlockSize      = aes.BlockSize
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
	ErrClosed          = e.New("closed")
)

type Checksumer interface {
	io.Writer

	Sum32() uint32
	Reset()
}

type ReadItem struct {
	isBusy bool
	Data   []byte
}

func (it *ReadItem) Release() {
	if !it.isBusy {
		panic(`should not happened`)
	}
	it.isBusy = false
	it.Data = it.Data[:0]
	readItemPool.Put(it)
}

type Session struct {
	locker sync.RWMutex

	id             uint64
	ctx            context.Context
	cancelFunc     context.CancelFunc
	state          SessionState
	identity       *Identity
	remoteIdentity *Identity
	options        SessionOptions

	keyExchanger   *keyExchanger
	backend        io.ReadWriteCloser
	messenger      [MessageTypeMax]*Messenger
	ReadChan       [MessageTypeMax]chan *ReadItem
	currentSecret  []byte
	cipher         cipher.Block
	previousCipher cipher.Block
	eventHandler   EventHandler
	writeDeferChan chan *writeItem
}

type SessionOptions struct {
	ErrorOnSequentialDecryptFailsCount *uint
	KeyExchangerOptions                KeyExchangerOptions
}

func (sess *Session) WaitForState(states ...SessionState) SessionState {
	return sess.state.WaitFor(states...)
}

func (sess *Session) GetState() SessionState {
	return sess.state.Get()
}

func (sess *Session) setState(state SessionState, cancelOnStates ...SessionState) (oldState SessionState) {
	oldState = sess.state.Set(state, cancelOnStates...)
	if sess.eventHandler.IsDebugEnabled() {
		sess.eventHandler.Debugf("setState: %v %v %v", state, cancelOnStates, oldState)
	}
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

func acquireReadItem() *ReadItem {
	item := readItemPool.Get().(*ReadItem)
	if item.isBusy {
		panic(`should not happened`)
	}
	item.isBusy = true
	return item
}

var nextSessionID uint64

func newSession(
	ctx context.Context,
	identity, remoteIdentity *Identity,
	backend io.ReadWriteCloser,
	eventHandler EventHandler,
	opts *SessionOptions,
) *Session {
	if eventHandler == nil {
		eventHandler = &dummyEventHandler{}
	}

	sess := &Session{
		id:             atomic.AddUint64(&nextSessionID, 1) - 1,
		identity:       identity,
		remoteIdentity: remoteIdentity,
		state:          SessionState_new,
		backend:        backend,
		eventHandler:   eventHandler,
		writeDeferChan: make(chan *writeItem, 1024),
	}
	if opts != nil {
		sess.options = *opts
	}
	if sess.options.ErrorOnSequentialDecryptFailsCount == nil {
		sess.options.ErrorOnSequentialDecryptFailsCount =
			&[]uint{DefaultErrorOnSequentialDecryptFailsCount}[0]
	}
	if *sess.options.ErrorOnSequentialDecryptFailsCount == 0 {
		sess.options.ErrorOnSequentialDecryptFailsCount = nil
	}

	sess.ctx, sess.cancelFunc = context.WithCancel(ctx)

	for i := 0; i < MessageTypeMax; i++ {
		sess.ReadChan[i] = make(chan *ReadItem, messageQueueLength)
	}

	panicIf(sess.init())
	return sess
}

func (sess *Session) ID() uint64 {
	return sess.id
}

func (sess *Session) init() error {
	sess.eventHandler.OnInit(sess)
	sess.startKeyExchange()
	sess.startReader()
	sess.startCloser()
	return nil
}

func (sess *Session) startReader() {
	go sess.readerLoop()
}

func (sess *Session) startCloser() {
	go func() {
		select {
		case <-sess.ctx.Done():
		}

		for _, messenger := range sess.messenger {
			if messenger == nil {
				continue
			}
			_ = messenger.Close()
		}
		for _, ch := range sess.ReadChan {
			close(ch)
		}

		sess.setState(SessionState_closed)
		if sess.eventHandler.IsDebugEnabled() {
			sess.eventHandler.Debugf("secureio session closed")
		}
	}()
}

func (sess *Session) isDone() bool {
	select {
	case <-sess.ctx.Done():
		return true
	default:
		return false
	}
}

func (sess *Session) readerLoop() {
	cannotDecryptCount := uint(0)
	var inputBuffer = make([]byte, maxPacketSize)
	var decryptedBuffer Buffer
	decryptedBuffer.Grow(maxPacketSize)

	for {
		select {
		case <-sess.ctx.Done():
			return
		default:
		}
		item := acquireReadItem()

		if sess.eventHandler.IsDebugEnabled() {
			sess.eventHandler.Debugf("n, err := sess.backend.Read(inputBuffer)")
		}
		n, err := sess.backend.Read(inputBuffer)
		if sess.eventHandler.IsDebugEnabled() {
			sess.eventHandler.Debugf("/n, err := sess.backend.Read(inputBuffer): %v %v", n, err)
		}
		if err != nil {
			sess.eventHandler.Error(sess, errors.Wrap(err))
			continue
		}
		if n == 0 {
			continue
		}

		hdr, payload, err := sess.decrypt(&decryptedBuffer, inputBuffer[:n])
		if sess.eventHandler.IsDebugEnabled() {
			sess.eventHandler.Debugf("sess.decrypt() result: %v %v %v; isMessengerSet:%v",
				hdr, payload, err,
				hdr != nil && hdr.Type > 0 &&
					hdr.Type < MessageTypeMax &&
					sess.messenger[hdr.Type] != nil,
			)
		}
		if err != nil && (err != ErrUnencrypted || hdr.Type != MessageType_keyExchange) {
			err = errors.Wrap(err)
			sess.eventHandler.Infof("cannot decrypt: %v", err)
			cannotDecryptCount++
			if sess.options.ErrorOnSequentialDecryptFailsCount != nil {
				if cannotDecryptCount >= *sess.options.ErrorOnSequentialDecryptFailsCount {
					sess.eventHandler.Error(sess, err)
				}
			}
			continue
		}
		cannotDecryptCount = 0

		if sess.messenger[hdr.Type] != nil {
			item.Release()
			if err := sess.messenger[hdr.Type].Handle(payload); err != nil {
				sess.eventHandler.Error(sess, errors.Wrap(err))
				hdr.Release()
				continue
			}
		} else {
			item.Data = item.Data[0:hdr.Length]
			copy(item.Data, payload)
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
	hdr := acquireMessageHeaders()

	decrypted.Reset()
	decrypted.Grow(len(encrypted))
	if sess.cipher == nil {
		copy(decrypted.Bytes, encrypted)
	} else {
		cipherDo(sess.cipher.Decrypt, decrypted.Bytes, encrypted)
	}

	if sess.eventHandler.IsDebugEnabled() {
		sess.eventHandler.Debugf("decrypting: %v %v %v", decrypted.Bytes, encrypted, decrypted.Len())
	}
	n, err := hdr.Read(decrypted.Bytes)
	decrypted.Offset += n
	if sess.eventHandler.IsDebugEnabled() {
		sess.eventHandler.Debugf("decrypted headers: %v %v %v %v %v", err, hdr, decrypted.Len(), decrypted.Cap(), decrypted.Offset)
	}
	if err != nil {
		hdr.Release()
		return nil, nil, errors.Wrap(err)
	}

	if len(decrypted.Bytes) < decrypted.Offset {
		hdr.Release()
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

		n, err2 = hdr.Read(decrypted.Bytes)
		decrypted.Offset += n
		if err2 != nil {
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

	n, err3 := hdr.Read(decrypted.Bytes)
	decrypted.Offset += n
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
	if int(decrypted.Offset)+int(hdr.Length) > len(decrypted.Bytes) {
		return errors.Wrap(ErrInvalidLength, hdr, decrypted.Offset, hdr.Length, len(decrypted.Bytes))
	}
	payload := decrypted.Bytes[decrypted.Offset : int(decrypted.Offset)+int(hdr.Length)]

	checksum := hdr.Checksum
	err := hdr.CalculateChecksum(payload)
	calculcatedChecksum := hdr.Checksum
	hdr.Checksum = checksum

	if err != nil {
		return errors.Wrap(err)
	}

	if calculcatedChecksum != checksum {
		return errors.Wrap(ErrInvalidChecksum, calculcatedChecksum, checksum, hdr, decrypted.Offset, hdr.Length, len(decrypted.Bytes))
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
	if sess.isDone() {
		return nil
	}
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
	if sess.eventHandler.IsDebugEnabled() {
		sess.eventHandler.Debugf("sendDeferred, %v", len(sess.writeDeferChan))
	}
	for {
		select {
		case item := <-sess.writeDeferChan:
			_, err := sess.WriteMessage(item.MsgType, item.Payload)
			if err != nil {
				sess.eventHandler.Error(sess, err)
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

	hdr := acquireMessageHeaders()
	n, err := func() (int, error) {
		hdr.Type = msgType
		hdr.Length = uint16(len(payload))
		err := hdr.CalculateChecksum(payload)
		if err != nil {
			return -1, err
		}

		buf := acquireBuffer()
		n, err := sess.writeMessageUsingBuffer(hdr, payload, buf)
		buf.Release()
		return n, err
	}()
	hdr.Release()

	return n, err
}

func (sess *Session) writeMessageUsingBuffer(
	hdr *messageHeaders,
	payload []byte,
	buf *Buffer,
) (n int, err error) {
	if sess.eventHandler.IsDebugEnabled() {
		sess.eventHandler.Debugf("writeMessageUsingBuffer: %v %v:%v", hdr, len(payload), payload)
	}

	buf.Grow(messageHeadersSize + len(payload))

	_, err = hdr.Write(buf.Bytes)
	if err != nil {
		return -1, errors.Wrap(err)
	}
	n = copy(buf.Bytes[messageHeadersSize:], payload)
	if n != len(payload) {
		err = errors.Wrap(ErrTooBig)
	}

	switch sess.GetState() {
	case SessionState_closed, SessionState_closing:
		return 0, errors.Wrap(ErrAlreadyClosed)
	}

	if sess.eventHandler.IsDebugEnabled() {
		sess.eventHandler.Debugf("sess.cipher == nil: %v", sess.cipher == nil)
	}
	if sess.cipher == nil || hdr.Type == MessageType_keyExchange {
		n, err = sess.backend.Write(buf.Bytes[:messageHeadersSize+n])
	} else {
		encrypted := acquireBuffer()
		size := roundSize(buf.Len(), cipherBlockSize)
		plainBytes := buf.Bytes[:size]

		encryptedBytes := encrypted.Bytes[:size]
		cipherDo(sess.cipher.Encrypt, encryptedBytes, plainBytes)
		if sess.eventHandler.IsDebugEnabled() {
			sess.eventHandler.Debugf("encrypted == %v; plain == %v", encryptedBytes, plainBytes)
		}
		n, err = sess.backend.Write(encryptedBytes)
		encrypted.Release()
	}

	return n, errors.Wrap(err)
}

func (sess *Session) startKeyExchange() {
	switch sess.setState(SessionState_keyExchanging, SessionState_closing, SessionState_closed) {
	case SessionState_keyExchanging, SessionState_closing, SessionState_closed:
		return
	}

	sess.keyExchanger = newKeyExchanger(
		sess.ctx,
		sess.identity,
		sess.remoteIdentity,
		sess.NewMessenger(MessageType_keyExchange), func(secret []byte) {
			// ok
			if sess.eventHandler.IsDebugEnabled() {
				sess.eventHandler.Debugf("got key: %v", secret)
			}
			sess.setSecret(secret)
			sess.setState(SessionState_established, SessionState_keyExchanging)

			sess.eventHandler.OnConnect(sess)

			sess.sendDeferred()
		}, func(err error) {
			// got error
			_ = sess.Close()
			sess.eventHandler.Error(sess, errors.Wrap(err))
		},
		&sess.options.KeyExchangerOptions,
	)
}

func (sess *Session) setMessenger(msgType MessageType, messenger *Messenger) {
	sess.LockDo(func() {
		if sess.messenger[msgType] != nil {
			err := errors.Wrap(sess.messenger[msgType].Close())
			if err != nil {
				sess.eventHandler.Error(sess, err)
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
		sess.currentSecret = key
		sess.cipher, err = aes.NewCipher(key)
		if sess.eventHandler.IsDebugEnabled() {
			sess.eventHandler.Debugf("new cipher with key: %v", key)
		}
		if err != nil {
			panic(err)
		}
	})
}

func (sess *Session) read(p []byte) (int, error) {
	item := <-sess.ReadChan[MessageType_dataPacketType0]
	if item == nil {
		return -1, errors.Wrap(ErrClosed)
	}
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

func (sess *Session) write(raw []byte) (int, error) {
	if len(raw)+messageHeadersSize > maxPayloadSize {
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
	sess.cancelFunc()
	return nil
}

func (sess *Session) GetEphemeralKey() []byte {
	return sess.currentSecret
}
