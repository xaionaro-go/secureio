package secureio

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/aead/chacha20/chacha"
	"github.com/xaionaro-go/udpnofrag"
	"golang.org/x/crypto/poly1305"

	xerrors "github.com/xaionaro-go/errors"
	"github.com/xaionaro-go/spinlock"
)

const (
	// DefaultErrorOnSequentialDecryptFailsCount defines the default value
	// of how many sequential messages is required be failed to be decrypted
	// to consider this fails to be erroneous situation.
	DefaultErrorOnSequentialDecryptFailsCount = 3

	// DefaultSendDelay defines the default messages aggregation delay.
	// It is used to merge small messages into one while sending it
	// through the backend to reduce overheads.
	DefaultSendDelay = time.Microsecond * 50

	// DefaultPacketIDStorageSize defines the default value for
	// SessionOptions.PacketIDStorageSize.
	//
	// Due to internal-implementation-specifics the value will
	// be automatically round-up to be aligned to 64.
	//
	// Don't use big values here (e.g. >4096):
	// T: O(n)
	// S: O(n)
	//
	// It seems unlikely to get a legitimate misordered packet
	// with misplacement more than 256 packets, while
	// the performance penalty is almost absent (the value is
	// small enough).
	DefaultPacketIDStorageSize = 256
)

const (
	updateKeyEveryNBytes = 1000000
	messageQueueLength   = 1024
	cipherBlockSize      = 1 // TODO: remove this obsolete constant
)

var (
	// timeNow is a function used instead of time.Now. It may be
	// reasonable to override it for unit-tests.
	timeNow = time.Now
)

func roundSize(size, blockSize uint32) uint32 {
	return (size + (blockSize - 1)) & ^(blockSize - 1)
}

// SessionID is the struct to represent an unique Session ID.
// CreateAt always grows (in never repeats within an application instance).
type SessionID struct {
	CreatedAt uint64
	Random    uint64
}

// Bytes returns SessionID as a byte array.
func (sessID *SessionID) Bytes() (result [16]byte) {
	binaryOrderType.PutUint64(result[0:], sessID.CreatedAt)
	binaryOrderType.PutUint64(result[8:], sessID.Random)
	return
}

// FillFromBytes fills SessionID using bytes slice.
// A bytes slice could be received via method Bytes()
func (sessID *SessionID) FillFromBytes(b []byte) {
	sessID.CreatedAt = binaryOrderType.Uint64(b[0:])
	sessID.Random = binaryOrderType.Uint64(b[8:])
}

// Session is an encrypted communication session which:
// * Verifies the remote side.
// * Uses ephemeral encryption keys ("cipher key") to encrypt/decrypt the traffic.
//
// When a Session is already in work, nothing else should Read-from/Write-to
// the backend io.ReadWriteCloser of the session.
//
// Session also implements io.ReadWriteCloser.
type Session struct {
	locker lockerRWMutex

	id                     SessionID
	ctx                    context.Context
	cancelFunc             context.CancelFunc
	state                  *sessionStateStorage
	identity               *Identity
	remoteIdentity         *Identity
	options                SessionOptions
	packetSizeLimit        uint32
	establishedPayloadSize uint32

	keyExchanger         *keyExchanger
	negotiator           *negotiator
	backend              io.ReadWriteCloser
	messenger            map[MessageType]*Messenger
	readChan             map[MessageType]chan *readItem
	currentSecrets       [][]byte
	cipherKeys           *[][]byte
	auxCipherKey         []byte
	waitForCipherKeyChan chan struct{}
	eventHandler         EventHandler
	stopWaitGroup        sync.WaitGroup
	isEstablished        chan struct{}

	bufferPool                   *bufferPool
	sendInfoPool                 *sendInfoPool
	readItemPool                 *readItemPool
	messageHeadersPool           *messageHeadersPool
	messagesContainerHeadersPool *messagesContainerHeadersPool

	delayedSendInfo          *SendInfo
	delayedWriteBuf          *buffer
	delayedWriteBufLocker    spinlock.Locker
	delayedSenderTimer       *time.Timer
	delayedSenderTimerLocker spinlock.Locker
	sendDelayedNowChan       chan *SendInfo
	sendDelayedCond          *sync.Cond
	sendDelayedCondLocker    sync.Mutex

	lastSendInfoSendID uint64

	keyExchangeCount            uint64
	sentMessagesCount           uint64
	receivedMessagesCount       uint64
	sequentialDecryptFailsCount uint64
	unexpectedPacketIDCount     uint64

	delayedSenderLoopCount uint32

	infoOutputChan  chan DebugOutputEntry
	debugOutputChan chan DebugOutputEntry

	receivedPacketIDs *packetIDStorage
	nextPacketID      uint64

	pauseWaitLocker sync.Mutex
	pauseLocker     spinlock.Locker
	isReadingValue  uint64
	pauseStartChan  chan struct{}

	readDeadlineLocker      spinlock.Locker
	readInterruptsRequested uint64
	readInterruptsHappened  uint64

	remoteSessionID *SessionID
}

// DebugOutputEntry is a structure of data which is being passed to a debugger
//
// See `(*Session).DebugOutputChan()` and `(*Session).InfoOutputChan()`.
type DebugOutputEntry struct {
	// Format has the same meaning as the first argument to `fmt.Printf`
	Format string

	// Args has the same meaning as the rest arguments (except the first one)
	// to `fmt.Printf`
	Args []interface{}
}

// SessionOptions is a structure to configure a Session while calling
// `(*Identity).NewSession`.
type SessionOptions struct {
	// EnableDebug enables the DEBUG messages to be passed through
	// `(*Session).DebugOutputChan()`. It causes performance penalty.
	//
	// This option will work only if the application was built
	// with tag "secureiodebug" (and/or "testlogging").
	EnableDebug bool

	// EnableInfo enables the INFO messages to be passed through
	// `(*Session).InfoOutputChan()`. It causes performance penalty.
	EnableInfo bool

	// SendDelay is the aggregation delay.
	// It is used to merge small messages into one while sending it
	// through the backend to reduce overheads.
	//
	// If it is set to a nil-value then DefaultSendDelay is used instead.
	//
	// If it is set to zero (`&[]time.Duration{0}[0]`) then no delay
	// will be performed and all messages will be sent right away.
	//
	// If you disable this option then you probably also would like
	// to disable the negotiator,
	// see `SessionOptions.NegotiatorOptions.Disable`.
	SendDelay *time.Duration

	// DetachOnMessagesCount is an amount of incoming messages after which
	// a Session will detach from the backend and close itself.
	// To use this feature the backend Reader should have
	// method SetReadDeadline or SetDeadline.
	//
	// If it is set to a zero-value then "never".
	DetachOnMessagesCount uint64

	// DetachOnSequentialDecryptFailsCount is an amount of sequential incoming
	// messages failed to be decrypted after which a Session will detach from
	// the backend and close itself.
	// To use this feature the backend Reader should have
	// method SetReadDeadline or SetDeadline.
	//
	// If it is set to a zero-value then "never".
	DetachOnSequentialDecryptFailsCount uint64

	// ErrorOnSequentialDecryptFailsCount is an amount of sequential incoming
	// messages failed to be decrypted after which a Session will report
	// and error.
	//
	// If it is set to a nil-value then
	// DefaultErrorOnSequentialDecryptFailsCount will be used instead.
	ErrorOnSequentialDecryptFailsCount *uint64

	// KeyExchangerOptions is the structure with options related only
	// to the key exchanging.
	//
	// See the description of fields of KeyExchangerOptions.
	KeyExchangerOptions KeyExchangerOptions

	// PayloadSizeLimit defines the maximal size of a messages passed
	// through the Session. The more this value is the more memory is consumed
	// and the larger payloads will be send through the underlying io.Writer.
	//
	// A whole packet (to be sent through the underlying io.Writer) will
	// be bigger (on size messagesContainerHeadersSize + messageHeadersSize).
	//
	// See also NegotiatorOptions.Disable.
	PayloadSizeLimit uint32

	// NegotiatorOptions is the structure with options related only
	// to the negotiation process. The negotiation process follows
	// after key-exchanging and called upon to find optimal settings
	// to communicate through given underlying io.ReadWriteCloser.
	NegotiatorOptions NegotiatorOptions

	// OnInitFuncs are the function which will be called right before Start
	// the Session (but after performing the self-configuration).
	OnInitFuncs []OnInitFunc

	// PacketIDStorageSize defines how many PacketID values could be
	// remembered to be able to check if packet was duplicated or
	// reordered.
	//
	// By default we try to eliminate possibility of duplicated packets
	// because it could be used by malefactors. So we remember
	// few (PacketIDStorageSize) highest values of received PacketID
	// values and:
	// * Drop if a packet has an ID we already remembered
	// * Drop if a packet has an ID lower than any remembered.
	//
	// If it's required to disable the mechanism of dropping packets
	// with invalid PacketID then set a negative value.
	//
	// Value "1" is a special value which enables the behaviour
	// where PacketID is allowed to grow only (no misordering is allowed).
	//
	// The default value (which is forced on a zero value) is
	// DefaultPacketIDStorageSize.
	PacketIDStorageSize int
}

// OnInitFunc is a function which will be called after a Session
// already setup everything to be ready-to-go, but not started, yet.
type OnInitFunc func(sess *Session)

// GetUnexpectedPacketIDCount returns the amount of packets which were
// ignored due to a wrong PacketID.
//
// See option `SessionOptions.AllowReorderingAndDuplication`.
func (sess *Session) GetUnexpectedPacketIDCount() uint64 {
	return atomic.LoadUint64(&sess.unexpectedPacketIDCount)
}

// DebugOutputChan returns the channel to receive the DEBUG messages from.
func (sess *Session) DebugOutputChan() <-chan DebugOutputEntry {
	return sess.debugOutputChan
}

// InfoOutputChan returns the channel to receive the INFO messages from.
func (sess *Session) InfoOutputChan() <-chan DebugOutputEntry {
	return sess.infoOutputChan
}

// WaitForState waits until the Session will get into any of the selected
// states.
func (sess *Session) WaitForState(ctx context.Context, states ...SessionState) SessionState {
	return sess.state.WaitFor(ctx, states...)
}

// GetState returns the current state of the Session.
//
// See SessionState.
func (sess *Session) GetState() SessionState {
	return sess.state.Load()
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

type sessionIDGetterType struct {
	rand *mathrand.Rand
	spinlock.Locker
	prevTime uint64
}

func (sessionIDGetter *sessionIDGetterType) Get() (result SessionID) {
	sessionIDGetter.LockDo(func() {
		for {
			result.CreatedAt = uint64(timeNow().UnixNano())
			if result.CreatedAt != sessionIDGetter.prevTime {
				break
			}
		}
		if result.CreatedAt <= sessionIDGetter.prevTime {
			result.CreatedAt = sessionIDGetter.prevTime + 1 // could happen due to a time-resynchronization
		}
		sessionIDGetter.prevTime = result.CreatedAt
	})

	result.Random = sessionIDGetter.rand.Uint64()
	return
}

var globalSessionIDGetter *sessionIDGetterType

func init() {
	var seedBytes [8]byte
	_, err := rand.Read(seedBytes[:])
	if err != nil {
		panic(err)
	}
	useed := binary.BigEndian.Uint64(seedBytes[:])
	seed := int64(useed & 0x7fffffffffffffff)
	if useed >= 0x8000000000000000 {
		seed = -seed - 1
	}
	globalSessionIDGetter = &sessionIDGetterType{
		rand: mathrand.New(mathrand.NewSource(seed)),
	}
}

func newSession(
	ctx context.Context,
	identity, remoteIdentity *Identity,
	backend io.ReadWriteCloser,
	eventHandler EventHandler,
	opts *SessionOptions,
) *Session {
	sess := &Session{}

	sess.init(
		ctx,
		identity, remoteIdentity,
		backend,
		eventHandler,
		opts,
	)

	panicIf(sess.start())
	return sess
}

func (sess *Session) init(
	ctx context.Context,
	identity, remoteIdentity *Identity,
	backend io.ReadWriteCloser,
	eventHandler EventHandler,
	opts *SessionOptions,
) {
	if eventHandler == nil {
		eventHandler = &dummyEventHandler{}
	}

	*sess = Session{
		id:                   globalSessionIDGetter.Get(),
		identity:             identity,
		remoteIdentity:       remoteIdentity,
		state:                newSessionStateStorage(),
		backend:              backend,
		eventHandler:         eventHandler,
		waitForCipherKeyChan: make(chan struct{}),
		sendDelayedNowChan:   make(chan *SendInfo),
		cipherKeys:           &[][][]byte{nil}[0],
		messenger:            make(map[MessageType]*Messenger),
		readChan:             make(map[MessageType]chan *readItem),
		isEstablished:        make(chan struct{}),
	}

	sess.ctx, sess.cancelFunc = context.WithCancel(ctx)
	if opts != nil {
		sess.options = *opts
	}

	sess.debugOutputChan = make(chan DebugOutputEntry, 1024)
	sess.infoOutputChan = make(chan DebugOutputEntry, 1024)

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
	if sess.options.PacketIDStorageSize == 0 {
		sess.options.PacketIDStorageSize = DefaultPacketIDStorageSize
	}
	if sess.options.PacketIDStorageSize > 0 {
		storageSize := uint(sess.options.PacketIDStorageSize)
		if storageSize == 1 {
			storageSize--
		}
		sess.receivedPacketIDs = newPacketIDStorage(storageSize)
	}

	if sess.options.PayloadSizeLimit == 0 {
		if IsLossyWriter(sess.backend) {
			sess.options.PayloadSizeLimit = atomic.LoadUint32(&payloadLossySizeLimit)
		} else {
			sess.options.PayloadSizeLimit = atomic.LoadUint32(&payloadSizeLimit)
		}
	}
	sess.updatePacketSizeLimit()
	sess.bufferPool = newBufferPool(uint(sess.GetPacketSizeLimit()))
	sess.establishedPayloadSize = sess.options.PayloadSizeLimit

	sess.delayedWriteBuf = sess.bufferPool.AcquireBuffer()
	sess.delayedWriteBuf.Bytes = sess.delayedWriteBuf.Bytes[:0]

	sess.sendInfoPool = newSendInfoPool(sess)
	sess.delayedSendInfo = sess.sendInfoPool.AcquireSendInfo(sess.ctx)

	sess.readItemPool = newReadItemPool()
	sess.messageHeadersPool = newMessageHeadersPool()
	sess.messagesContainerHeadersPool = newMessagesContainerHeadersPool()

	if sess.options.SendDelay != nil {
		sess.delayedSenderTimer = time.NewTimer(*sess.options.SendDelay)
		sess.delayedSenderTimer.Stop()
	}

	sess.sendDelayedCond = sync.NewCond(&sess.sendDelayedCondLocker)

	sess.readChan[MessageTypeReadWrite] = make(chan *readItem, messageQueueLength)

	psk := sess.options.KeyExchangerOptions.PSK
	if psk != nil {
		sess.auxCipherKey = hash(psk, Salt, []byte("auxCipherKey"))[:chacha.KeySize]
	}

	sess.setupBackend()
}

func (sess *Session) setupBackend() {
	var err error
	switch backend := sess.backend.(type) {
	case *net.UDPConn:
		err = wrapError(udpnofrag.UDPSetNoFragment(backend))
	}
	if err != nil {
		sess.error(err)
	}
}

func (sess *Session) getNextPacketID() uint64 {
	result := atomic.AddUint64(&sess.nextPacketID, 1)
	sess.debugf("next packet ID is %v", result)
	return result
}

// GetPayloadSizeLimit returns the currently configured MaxPayLoadSize
// of this Session.
//
// See also SessionOptions.PayloadSizeLimit and GetEstablishedPacketSize
func (sess *Session) GetPayloadSizeLimit() uint32 {
	return sess.options.PayloadSizeLimit
}

func (sess *Session) updatePacketSizeLimit() {
	sess.packetSizeLimit = sess.GetPayloadSizeLimit() +
		uint32(messagesContainerHeadersSize) +
		uint32(messageHeadersSize)
	sess.debugf("new max packet size is: %d", sess.packetSizeLimit)
}

func (sess *Session) setEstablishedPayloadSize(newValue uint32) {
	sess.debugf("updating the established payload size: %d -> %d",
		sess.establishedPayloadSize, newValue)
	atomic.StoreUint32(&sess.establishedPayloadSize, newValue)
}

// GetPacketSizeLimit returns the currently configured maximal packet size
// that could be sent through the backend io.ReadWriteCloser.
//
// The value is calculated based on SessionOptions.PayloadSizeLimit with
// addition of sizes of headers and paddings.
//
// See also GetEstablishedPacketSize
func (sess *Session) GetPacketSizeLimit() uint32 {
	return sess.packetSizeLimit
}

// GetEstablishedPacketSize returns the packet size limit received as result
// of negotiations. This is the real packet size used for communications.
//
// The value is calculated based on GetEstablishedPayloadSize() with
// addition of sizes of headers and paddings.
func (sess *Session) GetEstablishedPacketSize() uint32 {
	return sess.GetEstablishedPayloadSize() +
		uint32(messagesContainerHeadersSize) +
		uint32(messageHeadersSize)
}

// GetEstablishedPayloadSize returns the payload size limit received as result
// of negotiations. This is the real payload size used for communications.
func (sess *Session) GetEstablishedPayloadSize() uint32 {
	switch sess.state.Load() {
	case SessionStateEstablished:
		return sess.establishedPayloadSize
	}

	select {
	case <-sess.ctx.Done():
		return 0
	case <-sess.isEstablished:
		return sess.establishedPayloadSize
	}
}

// ID returns the unique (though the program execution) session ID
func (sess *Session) ID() SessionID {
	return sess.id
}

func (sess *Session) start() error {
	for _, onInitFunc := range sess.options.OnInitFuncs {
		onInitFunc(sess)
	}
	sess.eventHandler.OnInit(sess)
	sess.initNegotiator()
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

		sess.setState(SessionStateClosing, SessionStateClosed)

		recvMsgCount := atomic.LoadUint64(&sess.receivedMessagesCount)
		seqDecryptFailsCount := atomic.LoadUint64(&sess.sequentialDecryptFailsCount)
		sess.debugf("startBackendCloser() try: %v %v %v %v",
			sess.options.DetachOnMessagesCount, sess.options.DetachOnSequentialDecryptFailsCount,
			recvMsgCount, seqDecryptFailsCount)

		if sess.options.DetachOnMessagesCount != 0 &&
			recvMsgCount == sess.options.DetachOnMessagesCount {
			sess.debugf("startBackendCloser(): detach due to MessagesCount")
			if err := sess.interruptRead(); err != nil {
				sess.error(err)
			}
			return
		}

		if sess.options.DetachOnSequentialDecryptFailsCount != 0 &&
			seqDecryptFailsCount == sess.options.DetachOnSequentialDecryptFailsCount {
			sess.debugf("startBackendCloser(): detach due to FailsCount")
			if err := sess.interruptRead(); err != nil {
				sess.error(err)
			}
			return
		}

		if err := sess.interruptRead(); err != nil {
			sess.infof("unable to interrupt the Read(), closing the backend ReadWriteCloser")
			closeErr := sess.backend.Close()
			sess.debugf("sess.backend.Close() -> %v: %v ?= %v; %v ?= %v",
				closeErr, recvMsgCount, sess.options.DetachOnMessagesCount,
				seqDecryptFailsCount, sess.options.DetachOnSequentialDecryptFailsCount)
		}
	}()
}

func (sess *Session) isDone() bool {
	switch sess.state.Load() {
	case SessionStateNew, SessionStateKeyExchanging, SessionStateNegotiating,
		SessionStateEstablished, SessionStatePaused:
		return false
	}
	return true
}

func (sess *Session) isDoneSlow() bool {
	select {
	case <-sess.ctx.Done():
		return true
	default:
		return false
	}
}

// SetPause with value `true` temporary disables the reading process
// from the backend Reader. To use this method the backend Reader
// should has method SetReadDeadline or/and SetDeadline.
//
// SetPause(true) could be used only from state SessionStateEstablished.
//
// SetPause with value `false` re-enables the reading process from
// the backend Reader. It could be used only from state SessionStatePaused.
//
// Returns nil if the action was successful.
func (sess *Session) SetPause(newValue bool) (err error) {
	sess.debugf("SetPause(%v)", newValue)
	defer func() { sess.debugf("SetPause(%v) -> %v", newValue, err) }()

	badStates := []SessionState{
		SessionStateNew,
		SessionStateClosing,
		SessionStateClosed,
		SessionStateKeyExchanging,
		SessionStateNegotiating,
	}

	result := false
	var waitChan chan struct{}
	sess.pauseLocker.LockDo(func() {
		sess.lockDo(func() {
			if newValue {
				sess.pauseStartChan = make(chan struct{})
				if sess.setState(SessionStatePaused, badStates...) == SessionStateEstablished {
					sess.pauseWaitLocker.Lock()
					result = true
				} else {
					sess.pauseStartChan = nil
				}
			} else {
				if sess.setState(SessionStateEstablished, badStates...) == SessionStatePaused {
					sess.pauseWaitLocker.Unlock()
					result = true
				}
			}

		})

		switch {
		case !result:
			err = newErrCannotPauseOrUnpauseFromThisState()
		case result && newValue:
			waitChan = sess.pauseStartChan
			err = sess.interruptRead()
		}
	})

	if waitChan != nil {
		<-waitChan
	}

	return
}

func (sess *Session) waitForUnpause() {
	if sess.GetState() != SessionStatePaused {
		return
	}

	sess.debugf("blocked readerLoop() by a pause, waiting...")
	sess.pauseLocker.LockDo(func() {
		if sess.pauseStartChan == nil {
			return
		}
		close(sess.pauseStartChan)
		sess.pauseStartChan = nil
	})
	_ = sess.resetReadDeadline()
	sess.pauseWaitLocker.Lock()
	sess.pauseWaitLocker.Unlock()
	sess.debugf("the blocking of readerLoop() by a pause has finished, continuing...")
}

// isReadingValue returns true if the session is being waiting for Read from
// the backend to be returned (the reading from the backend is currently busy
// by this Session)
//
// See also `(*Session).SetPause`.
func (sess *Session) isReading() bool {
	return atomic.LoadUint64(&sess.isReadingValue) != 0
}
func (sess *Session) setIsReading(v bool) {
	var newValue uint64
	if v {
		newValue = 1
	} else {
		newValue = 0
	}
	atomic.StoreUint64(&sess.isReadingValue, newValue)
}

func (sess *Session) resetReadDeadline() (err error) {
	sess.readDeadlineLocker.LockDo(func() {
		sess.debugf("resetReadDeadline(): %v %v", sess.readInterruptsRequested, sess.readInterruptsHappened)
		if sess.readInterruptsRequested <= sess.readInterruptsHappened {
			return
		}
		err = sess.setBackendReadDeadline(timeNow().Add(time.Hour * 24 * 365 * 100))
		sess.readInterruptsHappened = sess.readInterruptsRequested
	})
	return
}

func (sess *Session) checkAndRememberPacketID(packetID uint64) (isOK bool) {
	if sess.receivedPacketIDs == nil {
		return true
	}
	sess.debugf("checkAndRememberPackerID(%v)", packetID)
	return sess.receivedPacketIDs.Push(packetID)
}

func (sess *Session) readerLoopCleanup() {
	sess.debugf("/readerLoop: state:%v isDoneSlow:%v", sess.state.Load(), sess.isDoneSlow())

	switch sess.state.Load() {
	case SessionStateKeyExchanging, SessionStateNegotiating:
		sess.startClosing()
	default:
		sess.setState(SessionStateClosing, SessionStateClosed)
		sess.cancelFunc()
	}

	for _, messenger := range sess.messenger {
		if messenger == nil {
			continue
		}
		_ = messenger.Close()
	}
	for _, ch := range sess.readChan {
		close(ch)
	}

	sess.setState(SessionStateClosed)
	sess.debugf("secureio session closed")
	close(sess.debugOutputChan)
	close(sess.infoOutputChan)
	_ = sess.resetReadDeadline()
	sess.debugf("//readerLoop: %v %v", sess.state.Load(), sess.isDoneSlow())
}

func (sess *Session) readerLoopReadError(err error) (shouldContinue bool) {
	if sess.isDone() {
		sess.debugf("readerLoop(): isDone()")
		return false
	}
	if strings.Index(err.Error(), `i/o timeout`) != -1 { // TODO: find a more strict way to check this error
		sess.debugf("sess.backend.Read(): an 'i/o timeout' error")
		sess.readDeadlineLocker.LockDo(func() {
			if sess.readInterruptsRequested <= sess.readInterruptsHappened {
				return
			}
			sess.debugf("sess.backend.Read(): OK, it seems it just was an interrupt, try again...")
			err = sess.setBackendReadDeadline(timeNow().Add(time.Hour * 24 * 365 * 100))
			sess.readInterruptsHappened = sess.readInterruptsRequested
		})
	}
	if err == nil {
		return true
	}

	if sess.eventHandler.Error(sess,
		xerrors.Errorf("unable to read from the backend (state == %v): %w",
			sess.state.Load(), err,
		),
	) {
		sess.debugf("a handled error, continuing")
	} else {
		sess.debugf("an unhandled error, closing the session")
		_ = sess.Close()
	}

	return true
}

func (sess *Session) readerLoopDecryptError(err error) (shouldContinue bool) {
	err = xerrors.Errorf("unable to decrypt: %w", err)
	sess.infof("%v", err)

	sequentialDecryptFailsCount := atomic.AddUint64(&sess.sequentialDecryptFailsCount, 1)
	if sess.options.ErrorOnSequentialDecryptFailsCount != nil {
		if sequentialDecryptFailsCount >= *sess.options.ErrorOnSequentialDecryptFailsCount {
			sess.eventHandler.Error(sess, err)
		}
	}

	if sequentialDecryptFailsCount >= sess.options.DetachOnSequentialDecryptFailsCount {
		sess.debugf(`reached limit "DetachOnSequentialDecryptFailsCount"`)
		return false
	}

	return true
}

func (sess *Session) readerLoop() {
	defer sess.readerLoopCleanup()

	var inputBuffer = make([]byte, sess.GetPacketSizeLimit())
	var decryptedBuffer buffer
	decryptedBuffer.Grow(uint(sess.GetPacketSizeLimit()))

	for !sess.isDone() {
		sess.setIsReading(true)
		sess.waitForUnpause()
		sess.ifDebug(func() { sess.debugf("readerLoop: n, err := sess.backend.Read(inputBuffer)") })
		n, err := sess.backend.Read(inputBuffer)
		sess.setIsReading(false)
		sess.ifDebug(func() {
			sess.debugf("readerLoop: /n, err := sess.backend.Read(inputBuffer): %v | %T:%v | %v", n, err, err, sess.state.Load())
		})
		if err != nil {
			if !sess.readerLoopReadError(err) {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}

		containerHdr, messagesBytes, err := sess.decrypt(&decryptedBuffer, inputBuffer[:n])
		if err != nil {
			if !sess.readerLoopDecryptError(err) {
				return
			}
			continue
		}

		packetID := containerHdr.PacketID.Value()
		if !sess.checkAndRememberPacketID(packetID) {
			sess.ifDebug(func() {
				sess.debugf(`wrong order: dropping the packet with ID %v`,
					packetID)
			})
			atomic.AddUint64(&sess.unexpectedPacketIDCount, 1)
			continue
		}
		atomic.StoreUint64(&sess.sequentialDecryptFailsCount, 0)

		sess.processIncomingMessages(containerHdr, messagesBytes)
		containerHdr.Release()
	}
	sess.debugf(`readerLoop(): loop finished`)
}

func (sess *Session) processIncomingMessages(
	containerHdr *messagesContainerHeaders,
	messagesBytes []byte,
) {
	msgCount := 0
	if sess.options.EnableDebug {
		defer func() {
			sess.debugf(`msgCount == %v`, msgCount)
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
			sess.eventHandler.Error(sess, xerrors.Errorf("unable to read a header: %w", err))
			return
		}
		if l-i < messageHeadersSize+uint(hdr.Length) {
			sess.eventHandler.Error(sess, newErrTooShort(messageHeadersSize+uint(hdr.Length), l-i))
			return
		}

		var receivedMessagesCount uint64
		if sess.options.DetachOnMessagesCount > 0 && hdr.Type != messageTypeKeyExchange && hdr.Type != messageTypeNegotiation {
			receivedMessagesCount = atomic.AddUint64(&sess.receivedMessagesCount, 1)
		}

		sess.processIncomingMessage(&hdr,
			messagesBytes[i+messageHeadersSize:i+messageHeadersSize+uint(hdr.Length)])

		if receivedMessagesCount > 0 && receivedMessagesCount >= sess.options.DetachOnMessagesCount {
			if sess.GetState() == SessionStateKeyExchanging && sess.keyExchanger.options.AnswersMode == KeyExchangeAnswersModeAnswerAndWait {
				sess.debugf(`reached limit "DetachOnMessagesCount". Last hdr == %v. But cannot detach (waiting for key-exchange answer, see AnswersMode).`, hdr)
			} else {
				sess.debugf(`reached limit "DetachOnMessagesCount". Last hdr == %v`, hdr)
				_ = sess.Close()
			}
			return
		}

		i += messageHeadersSize + uint(hdr.Length)
	}
	return
}

func (sess *Session) processIncomingMessage(hdr *messageHeadersData, payload []byte) {
	if sess.messenger[hdr.Type] != nil {
		if err := sess.messenger[hdr.Type].handle(payload[:hdr.Length]); err != nil {
			sess.eventHandler.Error(sess, xerrors.Errorf("unable to handle a message: %w", err))
		}
		return
	}

	item := sess.readItemPool.AcquireReadItem(sess.GetPacketSizeLimit())
	item.Data = item.Data[0:hdr.Length]
	copy(item.Data, payload[0:hdr.Length])

	var ch chan *readItem
	sess.rLockDo(func() {
		ch = sess.readChan[hdr.Type]
	})
	if ch == nil {
		return
	}
	ch <- item
	sess.debugf(`sent the message %v of length %v to the Messenger`, hdr, len(item.Data))
}

func (sess *Session) tryDecrypt(
	decrypted *buffer,
	containerHdr *messagesContainerHeaders,
	encrypted []byte,
	cipherKey []byte,
	iv []byte,
) (bool, error) {

	decrypted.Reset()
	decrypted.Grow(uint(len(encrypted)))

	if cipherKey != nil {
		decrypt(cipherKey, iv, decrypted.Bytes[decrypted.Offset:], encrypted)

		if len(encrypted) < 200 {
			sess.ifDebug(func() {
				sess.debugf("tryDecrypt: decrypted: iv:%v dec:%v enc:%v dec_len:%v cipher_key:%v",
					iv, decrypted.Bytes[decrypted.Offset:], encrypted, decrypted.Len(), cipherKey)
			})
		}
	} else {
		copy(decrypted.Bytes[decrypted.Offset:], encrypted)
	}

	n, err := containerHdr.ReadAfterIV(decrypted.Bytes[decrypted.Offset:])
	if n >= 0 {
		decrypted.Offset += uint(n)
	}
	sess.ifDebug(func() {
		sess.debugf("tryDecrypt: decrypted headers: err:%v hdr:%+v %v %v %v",
			err, &containerHdr.messagesContainerHeadersData, decrypted.Len(), decrypted.Cap(), decrypted.Offset)
	})
	if err != nil {
		return false, xerrors.Errorf("unable to read a decrypted header: %w", err)
	}

	err = sess.checkHeadersChecksum(cipherKey, containerHdr)
	if err != nil {
		sess.debugf("tryDecrypt: decrypting: headers checksum did not match (cipherKey == %v): %v",
			cipherKey, err)
		return false, nil
	}
	messagesBytes := decrypted.Bytes[decrypted.Offset:]
	err = sess.checkMessagesChecksum(cipherKey, containerHdr, messagesBytes)
	if err != nil {
		sess.debugf("tryDecrypt: decrypting: messages checksum did not match (cipherKey == %v): %v",
			cipherKey, err)
		return false, wrapError(err)
	}
	return true, nil
}

func (sess *Session) fillWithRemoteIV(
	ivBuf *buffer,
	containerHdr *messagesContainerHeaders,
) {
	if sess.remoteSessionID == nil {
		return
	}

	sessionIDBytes := sess.remoteSessionID.Bytes()
	ivLen := len(sessionIDBytes) + len(containerHdr.PacketID)
	ivBuf.Grow(uint(ivLen))
	copy(ivBuf.Bytes, sessionIDBytes[:])
	copy(ivBuf.Bytes[len(sessionIDBytes):], containerHdr.PacketID[:])
	sess.debugf("decrypt(): iv: %v:%v", ivLen, ivBuf.Bytes[:ivLen])
}

func (sess *Session) decryptPacketIDBytes(decrypted *buffer, encrypted []byte) (packetIDBytes []byte) {
	if sess.auxCipherKey == nil {
		packetIDBytes = encrypted
		return
	}

	packetIDBytes = decrypted.Bytes[:len(encrypted)]
	decrypt(sess.auxCipherKey, emptyIV, packetIDBytes, encrypted)
	decrypted.Offset += uint(len(encrypted))
	sess.debugf("decrypted the PacketID from %v to %v using key %v",
		encrypted, packetIDBytes, sess.auxCipherKey)
	return
}

func (sess *Session) decrypt(
	decrypted *buffer,
	encrypted []byte,
) (
	containerHdr *messagesContainerHeaders,
	messagesBytes []byte,
	err error,
) {
	if sess.isDebugEnabled() {
		defer func() {
			debugOutBytes := messagesBytes
			if len(debugOutBytes) > 200 {
				debugOutBytes = nil
			}
			sess.debugf("sess.decrypt() result: %v %v %v",
				containerHdr, debugOutBytes, err,
			)
		}()
	}

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

	containerHdr = sess.messagesContainerHeadersPool.AcquireMessagesContainerHeaders(sess)

	// Getting PacketID

	packetIDBytes := sess.decryptPacketIDBytes(decrypted, encrypted[:len(containerHdr.PacketID)])

	_, err = containerHdr.PacketID.Read(packetIDBytes)
	if err != nil {
		err = wrapError(err)
		return
	}

	// decrypting the rest:
	encrypted = encrypted[len(containerHdr.PacketID):]

	ivBuf := sess.bufferPool.AcquireBuffer()
	defer ivBuf.Release()
	sess.fillWithRemoteIV(ivBuf, containerHdr)

	defer func() {
		if err == nil {
			messagesBytes = decrypted.Bytes[decrypted.Offset:]
		}
	}()

	var done bool
	for _, cipherKey := range sess.GetCipherKeys() {
		if cipherKey == nil {
			continue
		}
		if done, err = sess.tryDecrypt(decrypted, containerHdr, encrypted,
			cipherKey, ivBuf.Bytes); done || err != nil {
			return
		}
	}

	if done, err = sess.tryDecrypt(decrypted, containerHdr, encrypted,
		sess.auxCipherKey, containerHdr.PacketID[:]); done || err != nil {
		return
	}

	err = newErrCannotDecrypt()
	return
}

func (sess *Session) checkHeadersChecksum(cipherKey []byte, containerHdr *messagesContainerHeaders) error {
	var calculatedChecksum [poly1305.TagSize]byte
	containerHdr.CalculateHeadersChecksumTo(cipherKey, &calculatedChecksum)

	if bytes.Compare(calculatedChecksum[:], containerHdr.ContainerHeadersChecksum[:]) != 0 {
		return xerrors.Errorf(
			"checkHeadersChecksum: %+v %v: %w",
			containerHdr.messagesContainerHeadersData, containerHdr.Length,
			newErrInvalidChecksum(containerHdr.ContainerHeadersChecksum[:], calculatedChecksum[:]),
		)
	}

	return nil
}

func (sess *Session) checkMessagesChecksum(cipherKey []byte, containerHdr *messagesContainerHeaders, messagesBytes []byte) error {
	var calculatedChecksum [poly1305.TagSize]byte
	containerHdr.CalculateMessagesChecksumTo(cipherKey, &calculatedChecksum, messagesBytes)

	if bytes.Compare(calculatedChecksum[:], containerHdr.MessagesChecksum[:]) != 0 {
		return xerrors.Errorf(
			"checkMessagesChecksum: %+v %v: %w",
			containerHdr.messagesContainerHeadersData, containerHdr.Length,
			newErrInvalidChecksum(containerHdr.MessagesChecksum[:], calculatedChecksum[:]),
		)
	}

	return nil
}

// lockDo locks the call of this method for other goroutines,
// executes the function `fn` and unlocks the call.
func (sess *Session) lockDo(fn func()) {
	sess.locker.LockDo(fn)
}

func (sess *Session) rLockDo(fn func()) {
	sess.locker.RLockDo(fn)
}

// NewMessenger returns a io.ReadWriteCloser for a specified MessageType.
// It overrides other handlers/messengers for this MessageType (if they set).
func (sess *Session) NewMessenger(msgType MessageType) *Messenger {
	if sess.isDoneSlow() {
		return nil
	}
	messenger := newMessenger(msgType, sess)
	sess.stopWaitGroup.Add(1)
	go func() {
		defer sess.stopWaitGroup.Done()
		messenger.WaitForClosure()
	}()
	sess.setMessenger(msgType, messenger)
	return messenger
}

type handlerByFuncs struct {
	dummyMessenger
	HandleFunc  func([]byte) error
	OnErrorFunc func(error)
}

func (h *handlerByFuncs) Handle(b []byte) error {
	if h.HandleFunc == nil {
		return nil
	}
	err := h.HandleFunc(b)
	if err != nil {
		return xerrors.Errorf("an error from h.HandleFunc(): %w", err)
	}
	return err
}
func (h *handlerByFuncs) HandleError(err error) {
	if h.OnErrorFunc == nil {
		return
	}
	h.OnErrorFunc(err)
}

// SetHandlerFuncs sets Handler functions for the specified MessageType:
// * `msgType` should be the same on the both sides of one communication;
// a MessageType could be received using function MessageTypeChannel().
// * `handle` handles incoming traffic/messages.
// * `onError` handles errors.
func (sess *Session) SetHandlerFuncs(
	msgType MessageType,
	handle func([]byte) error,
	onError func(error),
) {
	messenger := sess.NewMessenger(msgType)
	messenger.SetHandler(&handlerByFuncs{HandleFunc: handle, OnErrorFunc: onError})
}

// WriteMessage synchronously sends a message of MessageType `msgType`.
func (sess *Session) WriteMessage(
	msgType MessageType,
	payload []byte,
) (int, error) {
	sendInfo := sess.WriteMessageAsync(msgType, payload)

	sendInfo.Wait()
	err := sendInfo.Err
	sendInfo.Release()

	if err == nil {
		return len(payload), nil
	}
	return 0, err
}

// WriteMessageSingle synchronously sends a message of MessageType `msgType`
// as a single message (without merging with other messages, like
// if `SessionOptions.SendDelay` is negative).
func (sess *Session) WriteMessageSingle(
	msgType MessageType,
	payload []byte,
) (int, error) {
	hdr := sess.messageHeadersPool.AcquireMessageHeaders()
	hdr.Set(msgType, payload)
	defer hdr.Release()

	hdr.SetIsConfidential(msgType != messageTypeKeyExchange)

	return sess.writeMessageSingle(hdr, payload)
}

// GetCipherKeys returns the currently active cipher keys.
// Do not modify it, it's not a copy.
//
// It returns nil if there was no successful key exchange, yet.
func (sess *Session) GetCipherKeys() [][]byte {
	return *(*[][]byte)(
		atomic.LoadPointer(
			(*unsafe.Pointer)((unsafe.Pointer)(
				&sess.cipherKeys,
			)),
		),
	)
}

// GetCipherKeysWait waits until the first successful key exchange and
// returns the latest cipher key.
// Do not modify it, it's not a copy.
func (sess *Session) GetCipherKeysWait() [][]byte {
	cipherKeys := sess.GetCipherKeys()
	if len(cipherKeys) == secretIDs && cipherKeys[secretIDRecentBoth] != nil {
		return cipherKeys
	}

	select {
	case <-sess.waitForCipherKeyChan:
	case <-sess.ctx.Done():
		return nil
	}
	cipherKeys = sess.GetCipherKeys()
	if cipherKeys == nil {
		panic(`should not happened`)
	}
	return cipherKeys
}

// WriteMessageAsync asynchronously writes a message of MessageType `msgType`.
//
// Temporary hack (may be will be removed in future):
// If SendDelay is zero then the message will be sent synchronously, anyway.
func (sess *Session) WriteMessageAsync(
	msgType MessageType,
	payload []byte,
) (sendInfo *SendInfo) {
	defer func() { sess.debugf("/WriteMessageAsync() -> %+v", sendInfo) }()

	// if msgType == messageType_keyExchange or SendDelay is zero then
	//
	maxPayloadSize := atomic.LoadUint32(&sess.establishedPayloadSize)
	if uint32(len(payload)) > maxPayloadSize {
		sendInfo = sess.sendInfoPool.AcquireSendInfo(sess.ctx)
		sendInfo.Err = newErrPayloadTooBig(uint(maxPayloadSize), uint(len(payload)))
		close(sendInfo.c)
		return
	}

	hdr := sess.messageHeadersPool.AcquireMessageHeaders()
	hdr.Set(msgType, payload)
	defer hdr.Release()

	hdr.SetIsConfidential(msgType != messageTypeKeyExchange)

	if !hdr.IsConfidential() || sess.options.SendDelay == nil {
		sendInfo = sess.sendInfoPool.AcquireSendInfo(sess.ctx)
		n, err := sess.writeMessageSingle(hdr, payload)
		sendInfo.N = n
		sendInfo.Err = err
		close(sendInfo.c)
		return
	}

	return sess.writeMessageAsync(hdr, payload)
}

func (sess *Session) writeMessageSingle(
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

	return sess.sendMessages(
		hdr.IsConfidential(),
		isInternalMessageType(hdr.Type),
		buf.Bytes,
	)
}

func (sess *Session) writeMessageAsync(
	hdr *messageHeaders,
	payload []byte,
) (sendInfo *SendInfo) {
	if sess.options.EnableDebug {
		if len(payload) < 200 {
			sess.debugf("writeMessageAsync: %+v %v:%v", hdr, len(payload), payload)
		}
		defer func() {
			sess.debugf("/writeMessageAsync: %v", sendInfo)
		}()
	}

	if sess.options.SendDelay == nil {
		sendInfo = sess.sendInfoPool.AcquireSendInfo(sess.ctx)
		sendInfo.N, sendInfo.Err = sess.writeMessageSingle(hdr, payload)
		close(sendInfo.c)
		return
	}

	if !isInternalMessageType(hdr.Type) && sess.GetState() != SessionStateEstablished {
		select {
		case <-sess.ctx.Done():
			sendInfo = sess.sendInfoPool.AcquireSendInfo(sess.ctx)
			sendInfo.Err = newErrAlreadyClosed()
			close(sendInfo.c)
			return
		case <-sess.isEstablished:
		}
	}

	for {
		shouldWaitForSend := false
		sess.delayedWriteBufLockDo(func(buf *buffer) {
			packetSize := messagesContainerHeadersSize + uint(len(buf.Bytes)) + messageHeadersSize + uint(len(payload))
			maxPacketSize := sess.GetEstablishedPacketSize()
			if packetSize > uint(maxPacketSize) {
				if len(buf.Bytes) == 0 {
					sendInfo = sess.sendInfoPool.AcquireSendInfo(sess.ctx)
					sendInfo.Err = newErrPayloadTooBig(uint(maxPacketSize), packetSize)
					close(sendInfo.c)
					return
				}

				sess.debugf("no more space left in the buffer, sending now: %v (> %v)",
					packetSize, maxPacketSize)

				sendInfo = sess.delayedSendInfo
				shouldWaitForSend = true
				return
			}

			sendInfo = sess.appendToDelayedWriteBuffer(buf, hdr, payload)
		})
		if !shouldWaitForSend {
			return
		}
		sess.debugf("wait for previous messages to be sent")

		sess.waitForSend(sendInfo)
	}
}

func (sess *Session) waitForSend(sendInfo *SendInfo) {
	sendToSendDelayedNowChan := func() (result bool) {
		defer func() {
			result = recover() == nil
		}()
		if sendInfo.incRefCount() == 1 {
			panic(fmt.Sprintf("%+v", sendInfo))
		}
		select {
		case sess.sendDelayedNowChan <- sendInfo:
		default:
		}
		return
	}

	if !sendToSendDelayedNowChan() || sess.isDone() {
		sess.debugf("sess.sendDelayedNowChan is closed :(")
		sendInfo = sess.sendInfoPool.AcquireSendInfo(sess.ctx)
		sendInfo.Err = newErrCanceled()
		close(sendInfo.c)
		sess.sendDelayedCond.Broadcast()
		return
	}

	ticker := time.NewTicker(DefaultSendDelay * 2)
	defer ticker.Stop()
	for {
		select {
		case <-sess.ctx.Done():
			return
		case <-sendInfo.c:
			return
		case <-ticker.C:
			// TODO: fix this:
			// There's some race-condition somewhere in the code, so
			// the timer of sendDelayedLoop mis-fires sometimes and
			// the real message is never sent. As temporary solution
			// we just retry until the job will be done :(
			// This is what is "ticker" for.
			//
			// It should be reliable and does not affect performance,
			// but still it is very ugly...
			var bufLen int
			sess.delayedWriteBufLockDo(func(b *buffer) {
				bufLen = len(b.Bytes)
			})
			if bufLen == 0 {
				// OK, already sent, just exit
				return
			}
			// Still not sent, re-ask to send it :(
			sendToSendDelayedNowChan()
		}
	}
}

func (sess *Session) delayedWriteBufLockDo(fn func(*buffer)) {
	sess.delayedWriteBufLocker.LockDo(func() {
		fn(sess.delayedWriteBuf)
	})
}

func (sess *Session) appendToDelayedWriteBuffer(
	buf *buffer,
	hdr *messageHeaders,
	payload []byte,
) (sendInfo *SendInfo) {
	startIdx := uint(len(buf.Bytes))
	endIdx := startIdx + messageHeadersSize + uint(len(payload))
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
	if sendInfo.incRefCount() == 1 {
		panic(fmt.Sprintf("%+v", sendInfo))
	}
	sess.delayedSenderTimerLocker.LockDo(func() {
		sess.delayedSenderTimer.Reset(*sess.options.SendDelay)
	})
	atomic.StoreUint64(&sess.lastSendInfoSendID, sendInfo.sendID)

	buf.MetadataVariableUInt++
	sess.debugf("appendToDelayedWriteBuffer() -> %+v", sendInfo)
	return
}

func (sess *Session) sendDelayedNow() (uint64, uint) {
	sess.ifDebug(func() { sess.debugf(`sendDelayedNow()`) })

	// This lines should be before `Lock` because nothing
	// should (even very temporary) lock a routine between
	// `Lock` and `SwapPointer`. Otherwise function
	// `delayedWriteBufXLockDo` may work wrong (however it has 1000
	// tries within, so it's actually safe, but anyway this way is better).
	newSendInfo := sess.sendInfoPool.AcquireSendInfo(sess.ctx)
	nextBuf := sess.bufferPool.AcquireBuffer()
	nextBuf.Bytes = nextBuf.Bytes[:0]

	var oldSendInfo *SendInfo
	var buf *buffer
	sess.delayedWriteBufLocker.LockDo(func() {
		oldSendInfo, sess.delayedSendInfo = sess.delayedSendInfo, newSendInfo
		buf, sess.delayedWriteBuf = sess.delayedWriteBuf, nextBuf
	})

	if sess.options.EnableDebug {
		defer sess.debugf(`/sendDelayedNow(): len(buf.Bytes) == %v`,
			len(buf.Bytes))
	}

	sendID := oldSendInfo.sendID

	if len(buf.Bytes) > 0 {
		oldSendInfo.N, oldSendInfo.Err = sess.sendDelayedNowSyncFromBuffer(buf)
		sess.debugf("oldSendInfo -> %+v", oldSendInfo)
	}
	close(oldSendInfo.c)
	oldSendInfo.Release()
	bufLen := buf.Len()
	buf.Release()

	return sendID, bufLen
}

func (sess *Session) sendDelayedNowSyncFromBuffer(buf *buffer) (int, error) {
	messagesBytes := buf.Bytes

	n, err := sess.sendMessages(
		true,
		false,
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
	if atomic.AddUint32(&sess.delayedSenderLoopCount, 1) != 1 {
		panic("should not happen")
	}
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

	for func() bool {
		select {
		case sendInfo := <-sess.sendDelayedNowChan:
			defer sendInfo.Release()
			sess.debugf("delayedSenderLoop(): sendInfo := <-sess.sendDelayedNowChan: %+v; lastSendID == %v",
				sendInfo, lastSendID)
			if sendInfo.sendID <= lastSendID {
				return true
			}
		case <-sess.ctx.Done():
			sess.debugf("delayedSenderLoop(): <-sess.ctx.Done()")
			return false
		case <-sess.delayedSenderTimer.C:
			sess.debugf("delayedSenderLoop(): <-sess.delayedSenderTimer.c")
		}

		sendID, _ := sess.sendDelayedNow()
		if atomic.LoadUint64(&sess.lastSendInfoSendID) > sendID {
			sess.delayedSenderTimerLocker.LockDo(func() {
				if !sess.delayedSenderTimer.Stop() {
					<-sess.delayedSenderTimer.C
				}
				sess.delayedSenderTimer.Reset(*sess.options.SendDelay)
			})
		}

		lastSendID = sendID
		sess.sendDelayedCond.Broadcast()
		return true
	}() {
	}
}

func (sess *Session) sendMessages(
	isConfidential bool,
	isInternalMessage bool,
	messagesBytes []byte,
) (int, error) {

	// cipherKey

	var cipherKey []byte
	if isConfidential {
		cipherKeys := sess.GetCipherKeysWait()
		if cipherKeys == nil {
			return 0, newErrCanceled()
		}
		cipherKey = cipherKeys[secretIDRecentBoth]
	} else {
		cipherKey = sess.auxCipherKey
	}

	// containerHdr

	containerHdr := sess.messagesContainerHeadersPool.AcquireMessagesContainerHeaders(sess)
	err := containerHdr.Set(cipherKey, messagesBytes)
	if err != nil {
		return -1, wrapError(err)
	}
	defer containerHdr.Release()

	// plaintext buffer

	buf := sess.bufferPool.AcquireBuffer()
	defer buf.Release()
	buf.Grow(messagesContainerHeadersSize + uint(len(messagesBytes)))

	_, err = containerHdr.Write(buf.Bytes)
	if err != nil {
		return 0, wrapError(err)
	}

	messagesBytesOutStartIdx := messagesContainerHeadersSize
	messagesBytesOut := buf.Bytes[messagesBytesOutStartIdx:]
	n := copy(messagesBytesOut, messagesBytes)
	if !isInternalMessage {
		if sess.GetState() != SessionStateEstablished {
			select {
			case <-sess.ctx.Done():
				return 0, newErrAlreadyClosed()
			case <-sess.isEstablished:
			}
		}
		if uint32(messagesContainerHeadersSize)+uint32(len(messagesBytes)) > sess.GetEstablishedPacketSize() {
			err = newErrPayloadTooBig(uint(len(messagesBytesOut)), messagesContainerHeadersSize+uint(len(messagesBytes)))
			return 0, err
		}
	}
	if n != len(messagesBytes) {
		err = newErrPayloadTooBig(uint(len(messagesBytesOut)), messagesContainerHeadersSize+uint(len(messagesBytes)))
		return 0, err
	}

	sess.ifDebug(func() {
		sess.debugf("containerHdr == %+v; cipherKey == %v",
			&containerHdr.messagesContainerHeadersData, cipherKey)
	})

	// encrypt

	var outBytes []byte
	if cipherKey == nil {
		outBytes = buf.Bytes
	} else {
		encrypted := sess.bufferPool.AcquireBuffer()
		defer encrypted.Release()

		size := roundSize(uint32(buf.Len()), cipherBlockSize)
		buf.Grow(uint(size))
		encrypted.Grow(uint(size))

		plainBytes := buf.Bytes[:size]

		ivBuf := sess.bufferPool.AcquireBuffer()
		defer ivBuf.Release()

		if isConfidential {
			sessionIDBytes := sess.id.Bytes()
			ivBuf.Grow(uint(len(sessionIDBytes) + len(containerHdr.PacketID)))
			copy(ivBuf.Bytes, sessionIDBytes[:])
			copy(ivBuf.Bytes[len(sessionIDBytes):], containerHdr.PacketID[:])
		} else {
			ivBuf.Grow(uint(len(containerHdr.PacketID)))
			copy(ivBuf.Bytes, containerHdr.PacketID[:])
		}

		encryptedBytes := encrypted.Bytes[:size]
		encrypt(cipherKey, ivBuf.Bytes, encryptedBytes[len(containerHdr.PacketID):], plainBytes[len(containerHdr.PacketID):])
		if sess.auxCipherKey == nil {
			copy(encryptedBytes[:len(containerHdr.PacketID)], containerHdr.PacketID[:]) // copying the plain IV
		} else {
			encrypt(sess.auxCipherKey, emptyIV, encryptedBytes[:len(containerHdr.PacketID)], containerHdr.PacketID[:])
		}
		sess.ifDebug(func() {
			if len(encryptedBytes) >= 200 {
				return
			}
			sess.debugf("iv == %v; encrypted == %v; plain == %v, cipherKey == %+v",
				containerHdr.PacketID[:], encryptedBytes[len(containerHdr.PacketID):], plainBytes[len(containerHdr.PacketID):], cipherKey)
		})
		outBytes = encryptedBytes
	}

	// send/write

	if sess.isDone() {
		return 0, newErrAlreadyClosed()
	}

	n, err = sess.backend.Write(outBytes)
	sess.ifDebug(func() {
		outBytesPrint := interface{}("<too long>")
		if len(outBytes) < 200 {
			outBytesPrint = outBytes
		}

		tContainerHdr := &messagesContainerHeadersData{}
		if cipherKey == nil {
			_, _ = tContainerHdr.Read(outBytes)
		} else {
			tContainerHdr = nil
		}

		sess.debugf("sess.backend.Write(%v enc:%v[parsed_hdr:%+v]) -> %v, %v", outBytesPrint, cipherKey != nil, tContainerHdr, n, err)
	})

	return n, wrapError(err)
}

func (sess *Session) ifInfo(fn func()) {
	if !sess.options.EnableDebug {
		return
	}

	fn()
}

func (sess *Session) infof(format string, args ...interface{}) {
	sess.ifInfo(func() {
		defer func() { recover() }()
		select {
		case sess.infoOutputChan <- DebugOutputEntry{Format: format, Args: copyForDebug(args...)}:
		default:
		}
	})
}

func (sess *Session) error(err error) {
	sess.eventHandler.Error(sess, err)
}

// GetRemoteIdentity returns the remote identity.
// It's not a copy, don't modify the content.
func (sess *Session) GetRemoteIdentity() (result *Identity) {
	sess.rLockDo(func() {
		result = sess.remoteIdentity
	})
	return
}

func (sess *Session) onConnect() {
	defer sess.debugf("/onConnect()")

	sess.setState(SessionStateEstablished,
		SessionStateClosed, SessionStateClosing,
		SessionStateNew, SessionStateEstablished)

	close(sess.isEstablished)

	sess.eventHandler.OnConnect(sess)

	sess.debugf("established! sess.sendDelayedNow()")
	for {
		if _, l := sess.sendDelayedNow(); l == 0 {
			break
		}
		sess.debugf("something was sent on sess.sendDelayedNow()")
	}
	if sess.options.SendDelay != nil {
		sess.startDelayedSender()
	}
}

func (sess *Session) initNegotiator() {
	sess.negotiator = newNegotiator(
		sess.ctx,
		sess.NewMessenger(messageTypeNegotiation),
		sess.options.NegotiatorOptions,
		sess.onConnect,
		func(err error) {
			// got error
			_ = sess.Close()
			sess.eventHandler.Error(sess, wrapError(err))
		},
	)
}

func (sess *Session) onKeyExchangeSuccess() {
	if atomic.AddUint64(&sess.keyExchangeCount, 1) != 1 {
		return
	}

	sess.setState(SessionStateNegotiating,
		SessionStateClosed, SessionStateClosing,
		SessionStateNew, SessionStateEstablished, SessionStateNegotiating)

	err := sess.negotiator.Start()
	if err != nil {
		sess.error(err)
	}
}

func (sess *Session) onReceiveSecrets(secrets [][]byte) {
	if !sess.setSecrets(secrets) {
		// The same key as it was. Nothing to do.
		sess.debugf("got keys: the same as they were: %v", secrets)
		return
	}

	sess.debugf("got keys: new keys: %v", secrets)
}

func (sess *Session) startKeyExchange() {
	switch sess.setState(SessionStateKeyExchanging, SessionStateClosing, SessionStateClosed) {
	case SessionStateKeyExchanging, SessionStateClosing, SessionStateClosed:
		return
	}

	sess.stopWaitGroup.Add(1)

	sess.keyExchanger = newKeyExchanger(
		sess.ctx,
		sess.identity,
		sess.remoteIdentity,
		sess.NewMessenger(messageTypeKeyExchange),
		sess.onReceiveSecrets,
		sess.onKeyExchangeSuccess,
		func(err error) {
			// got error
			_ = sess.Close()
			sess.eventHandler.Error(sess, wrapError(err))
		},
		&sess.options.KeyExchangerOptions,
	)

	go func() {
		defer sess.stopWaitGroup.Done()
		sess.keyExchanger.WaitForClosure()
	}()
}

func (sess *Session) setMessenger(msgType MessageType, messenger *Messenger) {
	sess.lockDo(func() {
		if sess.messenger[msgType] != nil {
			err := sess.messenger[msgType].Close()
			if err != nil {
				sess.eventHandler.Error(sess, wrapError(err))
			}
		}
		sess.messenger[msgType] = messenger
		sess.readChan[msgType] = make(chan *readItem, messageQueueLength)
	})
}

func (sess *Session) setSecrets(newSecrets [][]byte) (result bool) {
	sess.lockDo(func() {
		sess.currentSecrets = newSecrets
		oldCipherKeys := sess.GetCipherKeys()
		newCipherKeys := make([][]byte, 0, len(newSecrets))
		changedCount := 0
		for idx, newSecret := range newSecrets {
			var newCipherKey []byte
			if newSecret != nil {
				newCipherKey = newSecret[:chacha.KeySize]
			}
			newCipherKeys = append(newCipherKeys, newCipherKey)
			if idx < len(oldCipherKeys) && bytes.Compare(newCipherKey, oldCipherKeys[idx]) == 0 {
				continue
			}
			changedCount++
		}
		if changedCount == 0 {
			return
		}

		atomic.StorePointer((*unsafe.Pointer)((unsafe.Pointer)(&sess.cipherKeys)), (unsafe.Pointer)(&newCipherKeys))

		if len(newCipherKeys) == secretIDs {
			// check if sess.waitForCipherKeyChan is already closed
			select {
			case _, ok := <-sess.waitForCipherKeyChan:
				if !ok {
					return
				}
			default:
			}

			// it not closed, yet? OK, close it:
			close(sess.waitForCipherKeyChan)
		}
		result = true
	})

	return
}

func (sess *Session) read(p []byte) (int, error) {
	ch := sess.readChan[MessageTypeReadWrite]
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

// Read implements io.Reader
func (sess *Session) Read(p []byte) (int, error) {
	return sess.read(p)
}

func (sess *Session) write(raw []byte) (int, error) {
	return sess.WriteMessage(MessageTypeReadWrite, raw)
}

// Write implements io.Writer
func (sess *Session) Write(p []byte) (int, error) {
	return sess.write(p)
}

func (sess *Session) setBackendReadDeadline(deadline time.Time) (err error) {
	defer func() { err = wrapError(err) }()

	if setReadDeadliner, ok := sess.backend.(interface{ SetReadDeadline(time.Time) error }); ok {
		err = setReadDeadliner.SetReadDeadline(deadline)
		if err != nil {
			return
		}
		return
	}

	if setDeadliner, ok := sess.backend.(interface{ SetDeadline(time.Time) error }); ok {
		err = setDeadliner.SetDeadline(deadline)
		if err != nil {
			return
		}
		return
	}

	return newErrCannotSetReadDeadline(sess.backend)
}

func (sess *Session) interruptRead() (err error) {
	defer func() { err = wrapError(err) }()
	if !sess.isReading() {
		return nil
	}
	sess.debugf("interrupting the Read()")

	sess.readDeadlineLocker.LockDo(func() {
		sess.readInterruptsRequested++
	})
	return sess.setBackendReadDeadline(timeNow())
}

func (sess *Session) startClosing() {
	defer sess.debugf("/startClosing()")

	go func() {
		select {
		case <-time.After(sess.keyExchanger.options.Timeout):
			sess.cancelFunc()
		case <-sess.ctx.Done():
		}
	}()
	for {
		if _, l := sess.sendDelayedNow(); l == 0 {
			break
		}
		sess.debugf("something was sent on sess.sendDelayedNow()")
	}
	sess.cancelFunc()
}

// Close implements io.Closer. It will send a signal to close the session,
// but it will return immediately (without waiting until everything will
// finish).
func (sess *Session) Close() error {
	switch sess.setState(SessionStateClosing, SessionStateClosed) {
	case SessionStateClosed, SessionStateClosing:
		return newErrAlreadyClosed()
	}
	sess.startClosing()
	return nil
}

// CloseAndWait sends the signal to close to the Session and waits until
// it will be done.
func (sess *Session) CloseAndWait() error {
	if err := sess.Close(); err != nil {
		return wrapError(err)
	}
	sess.WaitForClosure()
	return nil
}

// WaitForClosure waits until the Session will be closed and will finish
// everything.
func (sess *Session) WaitForClosure() {
	sess.stopWaitGroup.Wait()
}

// GetEphemeralKeys just returns the last generated shared keys
//
// It's not a copy, don't modify.
func (sess *Session) GetEphemeralKeys() [][]byte {
	return sess.currentSecrets
}

func (sess *Session) setRemoteSessionID(remoteSessionID *SessionID) {
	sess.debugf("setRemoteSessionID(%v)", remoteSessionID)
	sess.remoteSessionID = remoteSessionID
}
