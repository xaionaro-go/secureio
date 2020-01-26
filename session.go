package secureio

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	DefaultErrorOnSequentialDecryptFailsCount = 3
	DefaultSendDelay                          = time.Microsecond * 50
)

const (
	updateKeyEveryNBytes = 1000000
	messageQueueLength   = 1024
	cipherBlockSize      = aes.BlockSize
)

func roundSize(size, blockSize uint32) uint32 {
	return (size + (blockSize - 1)) & ^(blockSize - 1)
}

/*type Checksumer interface {
	io.Writer

	Sum64() uint64
	Reset()
}*/

type Session struct {
	locker sync.RWMutex

	id             uint64
	ctx            context.Context
	cancelFunc     context.CancelFunc
	state          SessionState
	identity       *Identity
	remoteIdentity *Identity
	options        SessionOptions
	maxPacketSize  uint32

	keyExchanger      *keyExchanger
	backend           io.ReadWriteCloser
	messenger         [MessageTypeMax]*Messenger
	ReadChan          [MessageTypeMax]chan *ReadItem
	currentSecret     []byte
	cipher            *cipher.Block
	previousCipher    *cipher.Block
	waitForCipherChan chan struct{}
	eventHandler      EventHandler
	stopWaitGroup     sync.WaitGroup

	bufferPool                   *bufferPool
	sendInfoPool                 *sendInfoPool
	readItemPool                 *readItemPool
	messageHeadersPool           *messageHeadersPool
	messagesContainerHeadersPool *messagesContainerHeadersPool

	delayedSendInfo       *SendInfo
	delayedWriteBuf       *Buffer
	delayedSenderTimer    *time.Timer
	delayedSenderLocker   sync.Mutex
	sendDelayedNowChan    chan *SendInfo
	sendDelayedCond       *sync.Cond
	sendDelayedCondLocker sync.Mutex

	lastSendInfoSendID uint64

	sentMessagesCount           uint64
	receivedMessagesCount       uint64
	sequentialDecryptFailsCount uint64
}

type SessionOptions struct {
	SendDelay                           *time.Duration
	DetachOnMessagesCount               uint64
	DetachOnSequentialDecryptFailsCount uint64
	ErrorOnSequentialDecryptFailsCount  *uint64
	KeyExchangerOptions                 KeyExchangerOptions
	MaxPayloadSize                      uint32
}

func (sess *Session) WaitForState(states ...SessionState) SessionState {
	return sess.state.WaitFor(states...)
}

func (sess *Session) GetState() SessionState {
	return sess.state.Get()
}

func (sess *Session) setState(state SessionState, cancelOnStates ...SessionState) (oldState SessionState) {
	oldState = sess.state.Set(state, cancelOnStates...)
	sess.debugf("setState: %v %v %v", state, cancelOnStates, oldState)
	return
}

func panicIf(err error) {
	if err != nil {
		panic(err)
	}
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
		id:                 atomic.AddUint64(&nextSessionID, 1) - 1,
		identity:           identity,
		remoteIdentity:     remoteIdentity,
		state:              SessionState_new,
		backend:            backend,
		eventHandler:       eventHandler,
		waitForCipherChan:  make(chan struct{}),
		sendDelayedNowChan: make(chan *SendInfo),
		cipher:             &[]cipher.Block{nil}[0],
		previousCipher:     &[]cipher.Block{nil}[0],
	}
	if opts != nil {
		sess.options = *opts
	}

	if sess.options.ErrorOnSequentialDecryptFailsCount == nil {
		sess.options.ErrorOnSequentialDecryptFailsCount =
			&[]uint64{DefaultErrorOnSequentialDecryptFailsCount}[0]
	}
	if *sess.options.ErrorOnSequentialDecryptFailsCount == 0 {
		sess.options.ErrorOnSequentialDecryptFailsCount = nil
	}

	if sess.options.SendDelay == nil {
		sess.options.SendDelay =
			&[]time.Duration{DefaultSendDelay}[0]
	}
	if *sess.options.SendDelay <= 0 {
		sess.options.SendDelay = nil
	}
	if sess.options.MaxPayloadSize == 0 {
		sess.options.MaxPayloadSize = atomic.LoadUint32(&maxPayloadSize)
	}
	sess.maxPacketSize = sess.GetMaxPayloadSize() +
		uint32(messagesContainerHeadersSize) +
		uint32(messageHeadersSize)
	sess.bufferPool = newBufferPool(uint(sess.GetMaxPacketSize()))

	sess.delayedWriteBuf = sess.bufferPool.AcquireBuffer()
	sess.delayedWriteBuf.Bytes = sess.delayedWriteBuf.Bytes[:0]

	sess.sendInfoPool = newSendInfoPool()
	sess.delayedSendInfo = sess.sendInfoPool.AcquireSendInfo()

	sess.readItemPool = newReadItemPool()
	sess.messageHeadersPool = newMessageHeadersPool()
	sess.messagesContainerHeadersPool = newMessagesContainerHeadersPool()

	sess.delayedSenderTimer = time.NewTimer(*sess.options.SendDelay)
	sess.delayedSenderTimer.Stop()

	sess.sendDelayedCond = sync.NewCond(&sess.sendDelayedCondLocker)

	sess.ctx, sess.cancelFunc = context.WithCancel(ctx)

	for i := 0; i < MessageTypeMax; i++ {
		sess.ReadChan[i] = make(chan *ReadItem, messageQueueLength)
	}

	panicIf(sess.init())
	return sess
}

func (sess *Session) GetMaxPayloadSize() uint32 {
	return sess.options.MaxPayloadSize
}

func (sess *Session) GetMaxPacketSize() uint32 {
	return sess.maxPacketSize
}

func (sess *Session) ID() uint64 {
	return sess.id
}

func (sess *Session) init() error {
	sess.eventHandler.OnInit(sess)
	sess.startKeyExchange()
	sess.startReader()
	sess.startBackendCloser()
	return nil
}

func (sess *Session) startReader() {
	sess.stopWaitGroup.Add(1)
	go func() {
		defer sess.stopWaitGroup.Done()
		sess.readerLoop()
	}()
}

func (sess *Session) startBackendCloser() {
	sess.stopWaitGroup.Add(1)
	go func() {
		defer sess.stopWaitGroup.Done()
		select {
		case <-sess.ctx.Done():
		}

		sess.setState(SessionState_closing, SessionState_closed)

		recvMsgCount := atomic.LoadUint64(&sess.receivedMessagesCount)
		seqDecryptFailsCount := atomic.LoadUint64(&sess.sequentialDecryptFailsCount)
		sess.debugf("startBackendCloser() try: %v %v %v %v",
			sess.options.DetachOnMessagesCount, sess.options.DetachOnSequentialDecryptFailsCount,
			recvMsgCount, seqDecryptFailsCount)

		if sess.options.DetachOnMessagesCount != 0 &&
			recvMsgCount == sess.options.DetachOnMessagesCount {
			return
		}

		if sess.options.DetachOnSequentialDecryptFailsCount != 0 &&
			seqDecryptFailsCount == sess.options.DetachOnSequentialDecryptFailsCount {
			return
		}

		sess.backend.Close()
		sess.debugf("sess.backend.Close(): %v ?= %v; %v ?= %v",
			recvMsgCount, sess.options.DetachOnMessagesCount,
			seqDecryptFailsCount, sess.options.DetachOnSequentialDecryptFailsCount)
	}()
}

func (sess *Session) isDoneFast() bool {
	switch sess.state.Load() {
	case SessionState_new, SessionState_keyExchanging,
		SessionState_established:
		return false
	case sessionState_inTransition:
		return sess.isDone()
	}
	return true
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
	defer func() {
		sess.debugf("\n/readerLoop: %v %v", sess.state.Load(), sess.isDone())

		sess.cancelFunc()

		for _, messenger := range sess.messenger {
			if messenger == nil {
				continue
			}
			_ = messenger.Close()
		}
		for idx, ch := range sess.ReadChan {
			close(ch)
			sess.ReadChan[idx] = nil
		}

		sess.setState(SessionState_closed)
		sess.debugf("secureio session closed")
	}()

	var inputBuffer = make([]byte, sess.GetMaxPacketSize())
	var decryptedBuffer Buffer
	decryptedBuffer.Grow(uint(sess.GetMaxPacketSize()))

	for !sess.isDoneFast() {
		sess.debugf("n, err := sess.backend.Read(inputBuffer)")
		n, err := sess.backend.Read(inputBuffer)
		sess.debugf("/n, err := sess.backend.Read(inputBuffer): %v | %v | %v", n, err, sess.state.Load())
		if err != nil {
			if sess.isDoneFast() {
				return
			}
			if !sess.eventHandler.Error(sess,
				wrapErrorf("unable to read from the backend (state == %v): %w",
					sess.state.Load(), err,
				),
			) {
				sess.debugf("an unhandled error, closing the session")
				_ = sess.Close()
			}

			continue
		}
		if n == 0 {
			continue
		}

		containerHdr, messagesBytes, err := sess.decrypt(&decryptedBuffer, inputBuffer[:n])
		if len(messagesBytes) < 200 {
			sess.debugf("sess.decrypt() result: %v %v %v",
				containerHdr, messagesBytes, err,
			)
		}

		if err != nil {
			err = wrapErrorf("unable to decrypt: %w", err)
			sess.eventHandler.Infof("%v", err)
			sequentialDecryptFailsCount := atomic.AddUint64(&sess.sequentialDecryptFailsCount, 1)
			if sess.options.ErrorOnSequentialDecryptFailsCount != nil {
				if sequentialDecryptFailsCount >= *sess.options.ErrorOnSequentialDecryptFailsCount {
					sess.eventHandler.Error(sess, err)
				}
			}
			if sequentialDecryptFailsCount >= sess.options.DetachOnSequentialDecryptFailsCount {
				sess.debugf(`reached limit "DetachOnSequentialDecryptFailsCount"`)
				return
			}
			continue
		}
		atomic.StoreUint64(&sess.sequentialDecryptFailsCount, 0)

		sess.processIncomingMessages(containerHdr, messagesBytes)
		containerHdr.Release()
	}
}

func (sess *Session) processIncomingMessages(
	containerHdr *messagesContainerHeaders,
	messagesBytes []byte,
) {
	msgCount := 0
	if sess.eventHandler.IsDebugEnabled() {
		defer func() {
			sess.eventHandler.Debugf(`msgCount == %v`, msgCount)
		}()
	}

	var hdr messageHeadersData
	l := umin(uint(len(messagesBytes)), uint(containerHdr.Length))
	for i := uint(0); i < l; {
		msgCount++

		if l-i < messageHeadersSize {
			sess.eventHandler.Error(sess, newErrTooShort(messageHeadersSize, l-i))
			return
		}
		_, err := hdr.Read(messagesBytes[i : i+messageHeadersSize])
		if err != nil {
			sess.eventHandler.Error(sess, wrapErrorf("unable to read a header: %w", err))
			return
		}
		if l-i < messageHeadersSize+uint(hdr.Length) {
			sess.eventHandler.Error(sess, newErrTooShort(messageHeadersSize+uint(hdr.Length), l-i))
			return
		}

		var receivedMessagesCount uint64
		if sess.options.DetachOnMessagesCount > 0 && hdr.Type != MessageType_keyExchange {
			receivedMessagesCount = atomic.AddUint64(&sess.receivedMessagesCount, 1)
		}

		sess.processIncomingMessage(&hdr,
			messagesBytes[i+messageHeadersSize:i+messageHeadersSize+uint(hdr.Length)])

		if receivedMessagesCount > 0 && receivedMessagesCount >= sess.options.DetachOnMessagesCount {
			sess.debugf(`reached limit "DetachOnMessagesCount". Last hdr == %v`, hdr)
			_ = sess.Close()
			return
		}

		i += messageHeadersSize + uint(hdr.Length)
	}
	return
}

func (sess *Session) processIncomingMessage(hdr *messageHeadersData, payload []byte) {
	if sess.messenger[hdr.Type] != nil {
		if err := sess.messenger[hdr.Type].Handle(payload[:hdr.Length]); err != nil {
			sess.eventHandler.Error(sess, wrapErrorf("unable to handle a message: %w", err))
		}
		return
	}

	item := sess.readItemPool.AcquireReadItem(sess.GetMaxPacketSize())
	item.Data = item.Data[0:hdr.Length]
	copy(item.Data, payload[0:hdr.Length])
	sess.debugf(`sent the message %v of length %v to a messenger`, hdr, len(item.Data))
	sess.ReadChan[hdr.Type] <- item
}

func (sess *Session) decrypt(
	decrypted *Buffer,
	encrypted []byte,
) (
	containerHdr *messagesContainerHeaders,
	messagesBytes []byte,
	err error,
) {
	defer func() {
		if err == nil {
			return
		}

		if containerHdr != nil {
			containerHdr.Release()
			containerHdr = nil
		}
		messagesBytes = nil
	}()

	if uint(len(encrypted)) < messagesContainerHeadersSize {
		err = newErrTooShort(messagesContainerHeadersSize, uint(len(encrypted)))
		return
	}

	containerHdr = sess.messagesContainerHeadersPool.AcquireMessagesContainerHeaders()

	// copying the IV (it's not encrypted)
	copy(containerHdr.IV[:], encrypted[:ivSize])
	encrypted = encrypted[ivSize:]

	tryDecrypt := func(blockCipher cipher.Block) (bool, error) {
		decrypted.Reset()
		decrypted.Grow(uint(len(encrypted)))

		if blockCipher != nil {
			decrypt(blockCipher, containerHdr.IV[:], decrypted.Bytes, encrypted)

			if len(encrypted) < 200 {
				sess.debugf("decrypted: iv:%v dec:%v enc:%v dec_len:%v cipher:%v",
					containerHdr.IV[:], decrypted.Bytes, encrypted, decrypted.Len(), blockCipher)
			}
		} else {
			copy(decrypted.Bytes, encrypted)
		}

		n, err := containerHdr.ReadAfterIV(decrypted.Bytes)
		if n >= 0 {
			decrypted.Offset += uint(n)
		}
		sess.debugf("decrypted headers: err:%v hdr:%+v %v %v %v",
			err, &containerHdr.messagesContainerHeadersData, decrypted.Len(), decrypted.Cap(), decrypted.Offset)
		if err != nil {
			return false, wrapErrorf("unable to read a decrypted header: %w", err)
		}

		err = sess.checkChecksum(containerHdr)
		if err != nil {
			sess.debugf("decrypting: checksum did not match (blockCipher == %v): %v",
				blockCipher, err)
			return false, nil
		}
		messagesBytes = decrypted.Bytes[decrypted.Offset:]
		return true, nil
	}

	{
		var done bool
		for _, cipherInstance := range []cipher.Block{
			sess.GetCipher(),
			sess.GetPreviousCipher(),
		} {
			if done, err = tryDecrypt(cipherInstance); done || err != nil {
				return
			}
		}

		if done, err = tryDecrypt(nil); done || err != nil {
			return
		}
	}

	err = newErrCannotDecrypt()
	return
}

func (sess *Session) checkChecksum(containerHdr *messagesContainerHeaders) error {
	checksum := containerHdr.ContainerHeadersChecksum
	err := containerHdr.CalculateChecksum(nil)
	calculatedChecksum := containerHdr.ContainerHeadersChecksum
	containerHdr.ContainerHeadersChecksum = checksum

	if err != nil {
		return wrapErrorf("unable to calculate a checksum: %w", err)
	}

	if calculatedChecksum != checksum {
		return wrapErrorf(
			"checkChecksum: %+v %v: %w",
			containerHdr.messagesContainerHeadersData, containerHdr.Length,
			newErrInvalidChecksum(checksum, calculatedChecksum),
		)
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

type handlerByFuncs struct {
	DummyMessenger
	HandleFunc  func([]byte) error
	OnErrorFunc func(error)
}

func (h *handlerByFuncs) Handle(b []byte) error {
	if h.HandleFunc == nil {
		return nil
	}
	err := h.HandleFunc(b)
	if err != nil {
		return wrapErrorf("an error from h.HandleFunc(): %w", err)
	}
	return err
}
func (h *handlerByFuncs) HandleError(err error) {
	if h.OnErrorFunc == nil {
		return
	}
	h.OnErrorFunc(err)
}

func (sess *Session) SetHandlerFuncs(
	msgType MessageType,
	handle func([]byte) error,
	onError func(error),
) {
	messenger := sess.NewMessenger(msgType)
	messenger.SetHandler(&handlerByFuncs{HandleFunc: handle, OnErrorFunc: onError})
}

func (sess *Session) GetDelayedWriteLength() (result MessageLength) {
	sess.delayedWriteBufRLockDo(func(buf *Buffer) {
		result = MessageLength(len(buf.Bytes))
	})
	return
}

func (sess *Session) WriteMessage(
	msgType MessageType,
	payload []byte,
) (int, error) {
	sendInfo := sess.WriteMessageAsync(msgType, payload)

	<-sendInfo.C
	err := sendInfo.Err
	sendInfo.Release()

	if err == nil {
		return len(payload), nil
	}
	return 0, err
}

func (sess *Session) GetCipher() cipher.Block {
	return *(*cipher.Block)(
		atomic.LoadPointer(
			(*unsafe.Pointer)((unsafe.Pointer)(
				&sess.cipher,
			)),
		),
	)
}

func (sess *Session) GetCipherWait() cipher.Block {
	cipher := sess.GetCipher()
	if cipher != nil {
		return cipher
	}

	<-sess.waitForCipherChan
	cipher = sess.GetCipher()
	if cipher == nil {
		panic(`should not happened`)
	}
	return cipher
}

func (sess *Session) GetPreviousCipher() cipher.Block {
	return *(*cipher.Block)(
		atomic.LoadPointer(
			(*unsafe.Pointer)((unsafe.Pointer)(
				&sess.previousCipher,
			)),
		),
	)
}

// if msgType == MessageType_keyExchange or SendDelay is zero then
// it will write the message synchronously anyway.
func (sess *Session) WriteMessageAsync(
	msgType MessageType,
	payload []byte,
) (sendInfo *SendInfo) {
	if uint32(len(payload)) > sess.GetMaxPayloadSize() {
		sendInfo = sess.sendInfoPool.AcquireSendInfo()
		sendInfo.Err = newErrPayloadTooBig(uint(sess.GetMaxPayloadSize()), uint(len(payload)))
		close(sendInfo.C)
		return
	}

	hdr := sess.messageHeadersPool.AcquireMessageHeaders()
	hdr.Set(msgType, payload)
	defer hdr.Release()

	if msgType == MessageType_keyExchange || sess.options.SendDelay == nil {
		var cipherInstance cipher.Block
		if msgType != MessageType_keyExchange {
			cipherInstance = sess.GetCipherWait()
		}
		n, err := sess.writeMessageSync(cipherInstance, hdr, payload)
		sendInfo = sess.sendInfoPool.AcquireSendInfo()
		sendInfo.N = n
		sendInfo.Err = err
		close(sendInfo.C)
		return
	}

	return sess.writeMessageAsync(hdr, payload)
}

func (sess *Session) writeMessageSync(
	cipherInstance cipher.Block,
	hdr *messageHeaders,
	payload []byte,
) (n int, err error) {
	defer func() {
		if err == nil {
			sess.incSentMessagesCount(1)
		}
	}()

	buf := sess.bufferPool.AcquireBuffer()
	defer buf.Release()

	buf.Grow(messageHeadersSize + uint(len(payload)))
	_, err = hdr.Write(buf.Bytes)
	if err != nil {
		return -1, wrapError(err)
	}

	copy(buf.Bytes[messageHeadersSize:], payload)

	containerHdr := sess.messagesContainerHeadersPool.AcquireMessagesContainerHeaders()
	err = containerHdr.Set(cipherInstance != nil, buf.Bytes)
	if err != nil {
		return -1, wrapError(err)
	}
	defer containerHdr.Release()

	return sess.sendMessages(
		cipherInstance,
		containerHdr,
		buf.Bytes,
	)
}

func (sess *Session) writeMessageAsync(
	hdr *messageHeaders,
	payload []byte,
) (sendInfo *SendInfo) {
	if sess.eventHandler.IsDebugEnabled() {
		if len(payload) < 200 {
			sess.debugf("writeMessageAsync: %+v %v:%v", hdr, len(payload), payload)
		}
		defer func() {
			sess.debugf("/writeMessageAsync: %v", sendInfo)
		}()
	}

	if sess.options.SendDelay == nil {
		sendInfo = sess.sendInfoPool.AcquireSendInfo()
		sendInfo.N, sendInfo.Err = sess.writeMessageSync(sess.GetCipherWait(), hdr, payload)
		close(sendInfo.C)
		return
	}

	for {
		shouldWaitForSend := false
		sess.delayedWriteBufLockDo(0, func(delayedWriteBufLockID LockID, buf *Buffer) {
			packetSize := messagesContainerHeadersSize + uint(len(buf.Bytes)) + messageHeadersSize + uint(len(payload))
			if packetSize > uint(sess.GetMaxPacketSize()) {
				if len(buf.Bytes) == 0 {
					sendInfo = sess.sendInfoPool.AcquireSendInfo()
					sendInfo.Err = newErrPayloadTooBig(uint(sess.GetMaxPacketSize()), packetSize)
					close(sendInfo.C)
					return
				}

				sess.debugf("no more space left in the buffer (%p), sending now: %v (> %v)",
					buf, packetSize, sess.GetMaxPacketSize())

				sendInfo = sess.delayedSendInfo
				shouldWaitForSend = true
				return
			}

			sendInfo = sess.appendToDelayedWriteBuffer(delayedWriteBufLockID, hdr, payload)
		})
		if !shouldWaitForSend {
			return
		}

		if !func() (result bool) {
			defer func() {
				result = recover() == nil
			}()
			sess.sendDelayedNowChan <- sendInfo
			return
		}() || sess.isDoneFast() {
			sess.debugf("sess.sendDelayedNowChan is closed :(")
			sendInfo = sess.sendInfoPool.AcquireSendInfo()
			sendInfo.Err = newErrCanceled()
			close(sendInfo.C)
			sess.sendDelayedCond.Broadcast()
			return
		}

		<-sendInfo.C
	}

	return
}

func (sess *Session) delayedWriteBufRLockDo(fn func(b *Buffer)) {
	sess.delayedWriteBufXLockDo(func(b *Buffer) error {
		return b.RLockDo(func() {
			fn(b)
		})
	})
}

func (sess *Session) delayedWriteBufLockDo(delayedWriteBufLockID LockID, fn func(LockID, *Buffer)) {
	sess.delayedWriteBufXLockDo(func(b *Buffer) error {
		return b.LockDo(delayedWriteBufLockID, func(lockID LockID) {
			fn(lockID, b)
		})
	})
}

func (sess *Session) delayedWriteBufXLockDo(fn func(*Buffer) error) {
	count := 0
	for {
		buf := (*Buffer)(atomic.LoadPointer((*unsafe.Pointer)((unsafe.Pointer)(&sess.delayedWriteBuf))))
		if !buf.incRefCount() {
			continue
		}
		bufCmp := (*Buffer)(atomic.LoadPointer((*unsafe.Pointer)((unsafe.Pointer)(&sess.delayedWriteBuf))))
		if buf != bufCmp {
			buf.Release()
			continue
		}
		err := fn(buf)
		buf.Release()
		switch {
		case err == nil:
			return
		case errors.As(err, &ErrMonopolized{}):
			count++
			// Actually `100000` is too much. "1" or "2" should be enough.
			// But just in case. See comments in `sendDelayedNow`.
			if count > 100000 {
				panic(`it seems the buffer wan't switched (an error in the code) and I got to a loop`)
			}

			runtime.Gosched() // wait until the buffer will be `Swap`-ped or de-`Monopolize`-d.
			continue
		default:
			panic(err)
		}
	}
}

func (sess *Session) appendToDelayedWriteBuffer(
	delayedWriteBufLockID LockID,
	hdr *messageHeaders,
	payload []byte,
) (sendInfo *SendInfo) {
	sess.delayedWriteBufLockDo(delayedWriteBufLockID, func(_ LockID, buf *Buffer) {
		startIdx := uint(len(buf.Bytes))
		endIdx := uint(startIdx) + messageHeadersSize + uint(len(payload))
		buf.Bytes = buf.Bytes[:endIdx]
		msgBuf := buf.Bytes[startIdx:endIdx]
		_, err := hdr.Write(msgBuf)
		if err != nil {
			sess.eventHandler.Error(sess, wrapError(err))
			buf.Bytes = buf.Bytes[:startIdx]
			return
		}

		copy(msgBuf[messageHeadersSize:], payload)

		// No atomicity is required here (with sendInfo) because delayedWriteBuf's Lock handles this problem
		sendInfo = sess.delayedSendInfo
		sendInfo.incRefCount()
		sess.delayedSenderTimer.Reset(*sess.options.SendDelay)
		atomic.StoreUint64(&sess.lastSendInfoSendID, sendInfo.SendID)

		buf.MetadataVariableUInt++
	})
	return
}

// this function couldn't be used concurrently
func (sess *Session) sendDelayedNow(
	delayedWriteBufLockID LockID,
	isSync bool,
) uint64 {
	sess.debugf(`sendDelayedNow(%v, %v)`, delayedWriteBufLockID, isSync)

	// This lines should be before `SetMonopolized` because nothing
	// should (even very temporary) lock a routine between
	// `SetMonopolized` and `SwapPointer`. Otherwise function
	// `delayedWriteBufXLockDo` may work wrong (however it has 1000
	// tries within, so it's actually safe, but anyway this way is better).
	newSendInfo := sess.sendInfoPool.AcquireSendInfo()
	nextBuf := sess.bufferPool.AcquireBuffer()
	nextBuf.Bytes = nextBuf.Bytes[:0]

	// Only this function changes sess.delayedWriteBuf pointer, but it's already locked by
	// the line above. So we can extract the value with `atomic` here.
	err := sess.delayedWriteBuf.SetMonopolized(delayedWriteBufLockID, true)
	if err != nil {
		panic(err)
	}

	var oldSendInfo *SendInfo
	// No atomicity is required here (with sendInfo) because delayedWriteBuf's Lock handles this problem.
	// That's why "SwapPointer" should be after this line (not before).
	oldSendInfo, sess.delayedSendInfo = sess.delayedSendInfo, newSendInfo

	// Atomic read is in `delayedWriteBufXLockDo`
	buf := (*Buffer)(atomic.SwapPointer(
		(*unsafe.Pointer)((unsafe.Pointer)(&sess.delayedWriteBuf)),
		(unsafe.Pointer)(nextBuf)),
	)

	defer sess.debugf(`/sendDelayedNow(%v, %v): len(buf.Bytes) == %v; oldSendInfo == %v`,
		delayedWriteBufLockID, isSync, len(buf.Bytes), oldSendInfo)

	callSend := func() {
		if len(buf.Bytes) > 0 {
			oldSendInfo.N, oldSendInfo.Err = sess.sendDelayedNowSyncFromBuffer(buf)
		}
		close(oldSendInfo.C)
		oldSendInfo.Release()
		buf.Release()
	}

	sendID := oldSendInfo.SendID
	if isSync {
		callSend()
	} else {
		go callSend()
	}

	return sendID
}

func (sess *Session) sendDelayedNowSyncFromBuffer(buf *Buffer) (int, error) {
	messagesBytes := buf.Bytes

	cipherInstance := sess.GetCipherWait()

	containerHdr := sess.messagesContainerHeadersPool.AcquireMessagesContainerHeaders()
	err := containerHdr.Set(cipherInstance != nil, messagesBytes)
	if err != nil {
		return -1, wrapError(err)
	}
	defer containerHdr.Release()

	n, err := sess.sendMessages(
		cipherInstance,
		containerHdr,
		messagesBytes,
	)
	if err != nil {
		return -1, wrapError(err)
	}

	sess.incSentMessagesCount(buf.MetadataVariableUInt)
	return n, nil
}

func (sess *Session) incSentMessagesCount(add uint) {
	newValue := atomic.AddUint64(&sess.sentMessagesCount, uint64(add))
	sess.debugf("sentMessagesCount -> %v", newValue)
}

func (sess *Session) startDelayedSender() {
	sess.stopWaitGroup.Add(1)
	go func() {
		defer sess.stopWaitGroup.Done()
		sess.delayedSenderLoop()
	}()
}

func (sess *Session) delayedSenderLoop() {
	sess.debugf("delayedSenderLoop()")
	defer sess.debugf("/delayedSenderLoop()")

	defer func() {
		close(sess.sendDelayedNowChan)
	}()
	var lastSendID uint64
	for {
		select {
		case sendInfo := <-sess.sendDelayedNowChan:
			sess.debugf("delayedSenderLoop(): sendInfo := <-sess.sendDelayedNowChan: %+v; lastSendID == %v",
				sendInfo, lastSendID)
			if sendInfo.SendID == lastSendID {
				continue
			}
		case <-sess.ctx.Done():
			sess.debugf("delayedSenderLoop(): <-sess.ctx.Done()")
			return
		case <-sess.delayedSenderTimer.C:
			sess.debugf("delayedSenderLoop(): <-sess.delayedSenderTimer.C")
		}

		sendID := sess.sendDelayedNow(0, true)
		if atomic.LoadUint64(&sess.lastSendInfoSendID) > sendID {
			if !sess.delayedSenderTimer.Stop() {
				<-sess.delayedSenderTimer.C
			}
			sess.delayedSenderTimer.Reset(*sess.options.SendDelay)
		}

		lastSendID = sendID
		sess.sendDelayedCond.Broadcast()
	}
}

func (sess *Session) sendMessages(
	cipherInstance cipher.Block,
	containerHdr *messagesContainerHeaders,
	messagesBytes []byte,
) (int, error) {
	buf := sess.bufferPool.AcquireBuffer()
	defer buf.Release()
	buf.Grow(messagesContainerHeadersSize + uint(len(messagesBytes)))

	_, err := containerHdr.Write(buf.Bytes)
	if err != nil {
		return 0, wrapError(err)
	}

	messagesBytesOutStartIdx := messagesContainerHeadersSize
	messagesBytesOut := buf.Bytes[messagesBytesOutStartIdx:]
	n := copy(messagesBytesOut, messagesBytes)
	if n != len(messagesBytes) || uint32(messagesContainerHeadersSize)+uint32(len(messagesBytes)) > sess.GetMaxPacketSize() {
		err = newErrPayloadTooBig(uint(len(messagesBytesOut)), messagesContainerHeadersSize+uint(len(messagesBytes)))
		return 0, err
	}

	if sess.isDoneFast() {
		return 0, newErrAlreadyClosed()
	}

	sess.debugf("containerHdr == %+v; cipherInstance -%v-> nil",
		&containerHdr.messagesContainerHeadersData, cipherInstance == nil)

	var outBytes []byte
	if !containerHdr.IsEncrypted() {
		outBytes = buf.Bytes
	} else {
		encrypted := sess.bufferPool.AcquireBuffer()
		defer encrypted.Release()

		size := roundSize(uint32(buf.Len()), cipherBlockSize)
		buf.Grow(uint(size))
		encrypted.Grow(uint(size))

		plainBytes := buf.Bytes[:size]

		encryptedBytes := encrypted.Bytes[:size]
		encrypt(cipherInstance, containerHdr.IV[:], encryptedBytes[ivSize:], plainBytes[ivSize:])
		copy(encryptedBytes[:ivSize], containerHdr.IV[:]) // copying the plain IV
		if len(encryptedBytes) < 200 {
			sess.debugf("iv == %v; encrypted == %v; plain == %v, cipherInstance == %+v",
				containerHdr.IV[:], encryptedBytes[ivSize:], plainBytes[ivSize:], cipherInstance)
		}
		outBytes = encryptedBytes
	}

	n, err = sess.backend.Write(outBytes)
	sess.ifDebug(func() {
		outBytesPrint := interface{}("<too long>")
		if len(outBytes) < 200 {
			outBytesPrint = outBytes
		}

		tContainerHdr := &messagesContainerHeadersData{}
		if !containerHdr.IsEncrypted() {
			_, _ = tContainerHdr.Read(outBytes)
		} else {
			tContainerHdr = nil
		}

		sess.debugf("sess.backend.Write(%v enc_%v:[%+v]) -> %v, %v", outBytesPrint, containerHdr.IsEncrypted(), tContainerHdr, n, err)
	})

	if err != nil {
		err = wrapError(err)
	}
	return n, err
}

func (sess *Session) ifDebug(fn func()) {
	if !sess.eventHandler.IsDebugEnabled() {
		return
	}

	fn()
}

func (sess *Session) debugf(format string, args ...interface{}) {
	sess.ifDebug(func() { sess.eventHandler.Debugf(format, args...) })
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
			sess.debugf("got key: %v", secret)
			sess.setSecret(secret)
			sess.setState(SessionState_established,
				SessionState_closed, SessionState_closing,
				SessionState_new, SessionState_established)

			sess.eventHandler.OnConnect(sess)

			sess.debugf("keyexchange: sess.sendDelayedNow()")
			for sess.sendDelayedNow(0, true) == 0 {
			}
			if sess.options.SendDelay != nil {
				sess.startDelayedSender()
			}
		}, func(err error) {
			// got error
			_ = sess.Close()
			sess.eventHandler.Error(sess, wrapError(err))
		},
		&sess.options.KeyExchangerOptions,
	)
}

func (sess *Session) setMessenger(msgType MessageType, messenger *Messenger) {
	sess.LockDo(func() {
		if sess.messenger[msgType] != nil {
			err := sess.messenger[msgType].Close()
			if err != nil {
				sess.eventHandler.Error(sess, wrapError(err))
			}
		}
		sess.messenger[msgType] = messenger
	})
}

func (sess *Session) setSecret(newSecret []byte) {
	sess.LockDo(func() {
		atomic.SwapPointer((*unsafe.Pointer)((unsafe.Pointer)(&sess.previousCipher)), (unsafe.Pointer)(sess.cipher))
		key := newSecret[:cipherBlockSize]
		sess.currentSecret = key
		cipher, err := aes.NewCipher(key)
		if err != nil {
			sess.eventHandler.Error(sess,
				wrapErrorf(`cannot create an AES cipher instance for key %v: %w`,
					key, err))
		}
		sess.debugf("new cipher with key: %v (err == %v)", key, err)
		close(sess.waitForCipherChan)
		if err != nil {
			_ = sess.Close()
			return
		}
		atomic.SwapPointer((*unsafe.Pointer)((unsafe.Pointer)(&sess.cipher)), (unsafe.Pointer)(&cipher))
	})
}

func (sess *Session) read(p []byte) (int, error) {
	ch := sess.ReadChan[MessageType_dataPacketType0]
	item := <-ch
	if item == nil {
		return -1, newErrAlreadyClosed()
	}
	if len(p) < len(item.Data) {
		return -1, newErrPayloadTooBig(uint(len(p)), uint(len(item.Data)))
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
	return sess.WriteMessage(MessageType_dataPacketType0, raw)
}

func (sess *Session) Write(p []byte) (int, error) {
	return sess.write(p)
}

func (sess *Session) Close() error {

	switch sess.setState(SessionState_closing) {
	case SessionState_closed, SessionState_closing:
		return newErrAlreadyClosed()
	}
	sess.cancelFunc()
	return nil
}
func (sess *Session) CloseAndWait() error {
	if err := sess.Close(); err != nil {
		return wrapError(err)
	}
	sess.WaitForClosure()
	return nil
}
func (sess *Session) WaitForClosure() {
	sess.stopWaitGroup.Wait()
}
func (sess *Session) GetEphemeralKey() []byte {
	return sess.currentSecret
}
