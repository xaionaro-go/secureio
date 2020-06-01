package secureio

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/binary"
	"sync"
	"time"

	"github.com/xaionaro-go/bytesextra"
	xerrors "github.com/xaionaro-go/errors"
)

const (
	// DefaultNegotiatorTotalTimeout is the default value for
	// `NegotiatorOptions.TotalTimeout`.
	DefaultNegotiatorTotalTimeout = time.Minute * 5

	// DefaultNegotiatorReadTimeout is the default value for
	// `NegotiatorOptions.ReadTimeout`.
	DefaultNegotiatorReadTimeout = time.Minute

	// DefaultNegotiatorMaxIterations is the default value for
	// `NegotiatorOptions.MaxIterations`.
	DefaultNegotiatorMaxIterations = 4
)

const (
	negotiationPingsPerIteration    = 3
	negotiationRedundancyFactor     = 3
	negotiationAdditionalWaitFactor = 3
	negotiationMinimalWait          = time.Millisecond
)

const (
	infinite = time.Hour * 24 * 365
)

type negotiator struct {
	locker           lockerMutex
	ctx              context.Context
	cancelFn         context.CancelFunc
	messenger        *Messenger
	options          NegotiatorOptions
	okFunc           func()
	errFunc          func(error)
	localLargestRTT  uint32
	remoteLargestRTT uint32
	recvChan         chan negotiatorRecvItem
	wgTasks          sync.WaitGroup
	stageChan        chan struct{}
	remoteEndOnce    sync.Once
}

type negotiatorRecvItem struct {
	MessageSize uint32
	IterationID uint32
}

// NegotiatorEnable controls if negotiations should be enabled.
type NegotiatorEnable uint8

const (
	// NegotiatorEnableAuto enables negotiations only if detects an UDP
	// connection.
	NegotiatorEnableAuto = NegotiatorEnable(iota)

	// NegotiatorEnableFalse disables negotiations.
	NegotiatorEnableFalse

	// NegotiatorEnableTrue enables negotiations
	NegotiatorEnableTrue
)

// NegotiatorOptions is the structure with options related only
// to the negotiation process. The negotiation process follows
// after key-exchanging and called upon to find optimal settings
// to communicate through given underlying io.ReadWriteCloser.
type NegotiatorOptions struct {
	// Enable controls if negotiations should be enabled.
	Enable NegotiatorEnable

	// ReadTimeout defines how long the negotiator is allowed to wait
	// without any incoming message before consider the connection
	// unreliable and return an error.
	//
	// The default value is DefaultNegotiatorReadTimeout
	//
	// Use a negative value to disable this behavior.
	ReadTimeout time.Duration

	// TotalTimeout defines how long the negotiator is allowed to wait
	// in total before give up and just try to use the best-yet-found
	// settings. And if the timeout was reached and there was no
	// pong-responses at all (there is no of any found settings) then
	// return an error
	//
	// The default value is DefaultNegotiatorTotalTimeout
	//
	// Use a negative value to disable this behavior.
	TotalTimeout time.Duration

	// MaxIterations define how many iterations of probing for packet
	// size is permitted. The more this value the more time will
	// be required to negotiate, but the value of the optimal packet
	// size will be more precise
	//
	// The default value is DefaultNegotiatorMaxIterations
	MaxIterations uint32
}

func newNegotiator(
	ctx context.Context,
	messenger *Messenger,
	options NegotiatorOptions,
	okFunc func(),
	errFunc func(error),
) *negotiator {
	if options.TotalTimeout == 0 {
		options.TotalTimeout = DefaultNegotiatorTotalTimeout
	}
	if options.ReadTimeout == 0 {
		options.ReadTimeout = DefaultNegotiatorReadTimeout
	}
	if options.MaxIterations == 0 {
		options.MaxIterations = DefaultNegotiatorMaxIterations
	}

	if errFunc == nil {
		errFunc = messenger.sess.error
	}

	n := &negotiator{
		ctx:       ctx,
		messenger: messenger,
		options:   options,
		okFunc:    okFunc,
		errFunc:   errFunc,
		recvChan:  make(chan negotiatorRecvItem, 32),
		stageChan: make(chan struct{}),
	}

	n.messenger.SetHandler(n)
	return n
}

func (n *negotiator) isEnabled() bool {
	switch n.options.Enable {
	case NegotiatorEnableAuto:
		return IsLossyWriter(n.messenger.sess.backend)
	case NegotiatorEnableTrue:
		return true
	case NegotiatorEnableFalse:
		return false
	default:
		n.messenger.sess.infof("invalid value of negotiator.Options.Enable: %d", n.options.Enable)
		return true
	}
}

func (n *negotiator) Start() (err error) {
	n.lockDo(func() {
		if n.cancelFn != nil {
			err = newErrAlreadyStarted()
			return
		}

		if n.options.TotalTimeout > 0 {
			n.ctx, n.cancelFn = context.WithTimeout(n.ctx, n.options.TotalTimeout)
		} else {
			n.ctx, n.cancelFn = context.WithCancel(n.ctx)
		}
	})
	if err != nil {
		return
	}

	if !n.isEnabled() {
		n.debugf("skip")
		n.okFunc()
		_ = n.Close()
		return
	}
	n.debugf("run")

	n.wgTasks.Add(1)
	go func() {
		defer n.wgTasks.Done()
		n.finalizer()
	}()

	n.wgTasks.Add(1)
	go func() {
		defer n.wgTasks.Done()
		n.pingSenderLoop()
		n.debugf("the local side has ended")
		n.stageChan <- struct{}{}
	}()
	return
}

func (n *negotiator) finalizer() {
	n.debugf("finalizer(): waiting for a signal...")
	defer n.debugf("/finalizer()")

	stageID := 0
	for {
		select {
		case <-n.stageChan:
			stageID++
			n.debugf("finalizer: stageID == %d", stageID)
			if stageID == 2 {
				n.finalize()
				return
			}
		case <-n.ctx.Done():
			return
		}
	}
}

func (n *negotiator) finalize() {
	maxPayloadSize := u32min(n.localLargestRTT, n.remoteLargestRTT)
	n.debugf("finalize: payloadSizeLimit == %d", maxPayloadSize)
	n.messenger.sess.setEstablishedPayloadSize(maxPayloadSize)
	n.okFunc()
	go n.Close()
}

func (n *negotiator) isCtxDone() bool {
	select {
	case <-n.ctx.Done():
		return true
	default:
		return false
	}
}

func (n *negotiator) sendPing(iterationID uint32, size uint32) (err error) {
	defer func() { err = wrapError(err) }()

	msg := &negotiationPingPongMessage{}
	msgSize := binary.Size(msg)
	msg.IterationID = iterationID
	msg.MessageSubType = 1
	buf := make([]byte, size)
	for idx := range buf[msgSize:] {
		buf[msgSize+idx] = uint8(idx)
	}

	err = binary.Write(bytesextra.NewWriter(buf), binaryOrderType, msg)
	if err != nil {
		return
	}

	checksum := sha512.Sum512(buf[65:])
	copy(buf[1:], checksum[:])

	n.debugf("sendPing(%d, %d): %v", iterationID, size, buf[:msgSize])
	_, err = n.messenger.WriteSingle(buf)
	if err != nil {
		return
	}

	return
}

func (n *negotiator) pingSenderLoop() {
	n.debugf("pingSenderLoop()")
	defer n.debugf("/pingSenderLoop()")

	payloadSizeLimit := n.messenger.sess.GetPayloadSizeLimit()

	curIterationID := uint32(0)
	min := uint32(147)                            // the minimal payload size to negotiate
	max := n.messenger.sess.GetPayloadSizeLimit() // the maximal payload size to negotiate
pingSenderEnd:
	for !n.isCtxDone() {
		n.debugf("pingSenderLoop: curIterationID:%d; min:%d; max:%d", curIterationID, min, max)

		steps := uint(negotiationPingsPerIteration)
		var step float64
		switch {
		case max-min <= 3: // max force to be higher than the real value, so it could be differ even on three and it's OK
			n.debugf("I have all the information I need. Sending the notification and closing the pingSenderLoop...")
			break pingSenderEnd
		case max-min < negotiationPingsPerIteration:
			step = 1
			steps = uint(max - min)
		default:
			step = float64(max-min) / float64(negotiationPingsPerIteration)
		}
		for i := int(steps); i >= 0; i-- {
			size := min + uint32(0.999+step*float64(i))
			for r := 0; r < negotiationRedundancyFactor; r++ {
				if n.isCtxDone() {
					n.debugf("n.isCtxDone()")
					return
				}
				n.debugf("n.sendPing() for curIterationID:%d i:%d r:%d",
					curIterationID, i, r)
				err := n.sendPing(curIterationID, size)
				if err != nil {
					n.messenger.sess.error(err)
					if err.(*xerrors.Error).Has(ErrAlreadyClosed{}) {
						go n.Close()
					} else {
						n.errFunc(err)
					}
				}
			}
		}
		readTimeout := n.options.ReadTimeout
		if readTimeout <= 0 {
			n.options.ReadTimeout = infinite
		}
		n.debugf("pingSenderLoop: steps:%d step:%f", steps, step)

		var firstReceived time.Duration
		startTime := time.Now()
		var nextMin, nextMax uint32

	negotiatorPingSenderLoopCollectFor:
		for {
			var collectUntil time.Time
			if firstReceived > 0 {
				collectUntil = startTime.Add(firstReceived*negotiationAdditionalWaitFactor + negotiationMinimalWait)
			} else {
				collectUntil = startTime.Add(infinite)
			}
			n.debugf("pingSenderLoop: startTime:%v firstReceived:%v collectDuration:%v",
				startTime, firstReceived, time.Until(collectUntil))
			select {
			case recvItem := <-n.recvChan:
				if recvItem.MessageSize > nextMin {
					nextMin = recvItem.MessageSize
					nextMax = nextMin + uint32(step+1) // we need to round the "step" up
				}
				if firstReceived == 0 && recvItem.IterationID == curIterationID {
					firstReceived = time.Since(startTime)
				}
			case <-time.After(time.Until(collectUntil)):
				break negotiatorPingSenderLoopCollectFor
			case <-time.After(readTimeout):
				n.errFunc(newErrNegotiationTimeout("read collectUntil"))
				return
			case <-n.ctx.Done():
				n.errFunc(newErrNegotiationCancelled("ctx is done"))
				return
			}
		}

		if nextMin == min {
			n.debugf("pingSenderLoop(): nextMin == min (not changed)")
			break
		}

		if nextMin == payloadSizeLimit {
			n.debugf("pingSenderLoop(): nextMin == payloadSizeLimit (already maximum possible value)")
			break
		}

		curIterationID++

		min = nextMin

		if nextMax >= max {
			// May be we lost an useful packet on the previous iteration time, let's recheck a little-bit higher :(
			max = nextMax * uint32(umin(2, negotiationRedundancyFactor, negotiationPingsPerIteration))
		} else {
			max = nextMax + 1 /* permit a higher max to check if we lost something of the previous iteration */
		}
		if max > payloadSizeLimit {
			max = payloadSizeLimit
		}

		if curIterationID >= n.options.MaxIterations {
			n.debugf("pingSenderLoop(): curIterationID >= n.options.MaxIterations")
			return
		}
	}
	n.debugf("pingSenderLoop(): reached the end, sending the control info before return")
	for r := 0; r < negotiationRedundancyFactor; r++ {
		n.sendControl(true)
	}
}

func (n *negotiator) sendControl(isNegotiationEnd bool) {
	n.debugf("sendControl(%v)", isNegotiationEnd)
	msg := &negotiationControlMessage{}
	msg.MessageSubType = 0
	n.lockDo(func() {
		msg.LargestRTT = n.localLargestRTT
	})
	msg.Flags.SetIsNegotiationEnd(isNegotiationEnd)
	var buf bytes.Buffer
	err := binary.Write(&buf, binaryOrderType, msg)
	if err != nil {
		n.errFunc(wrapError(err))
		return
	}
	_, err = n.messenger.WriteSingle(buf.Bytes())
	if err != nil {
		n.errFunc(wrapError(err))
		return
	}
}

func (n *negotiator) lockDo(fn func()) {
	n.locker.LockDo(fn)
}

func (n *negotiator) parseMessage(msg interface{}, b []byte) (err error) {
	defer func() { err = wrapError(err) }()

	if len(b) < binary.Size(msg) {
		return newErrTooShort(uint(binary.Size(negotiationControlMessage{})), uint(len(b)))
	}
	return binary.Read(bytes.NewReader(b), binaryOrderType, msg)
}

func (n *negotiator) handleControlMessage(b []byte) (err error) {
	defer func() { err = wrapError(err) }()
	msg := &negotiationControlMessage{}
	err = n.parseMessage(msg, b)
	if err != nil {
		return
	}
	n.debugf("handleControlMessage(): len(b)==%d; msg==%+v", len(b), msg)

	n.lockDo(func() {
		n.remoteLargestRTT = msg.LargestRTT
		n.debugf("n.remoteLargestRTT == %d", n.remoteLargestRTT)
	})

	if msg.Flags.IsNegotiationEnd() {
		n.remoteEndOnce.Do(func() {
			n.debugf("the remote side has ended")
			n.stageChan <- struct{}{}
		})
	}
	return
}

func (n *negotiator) debugf(fmt string, args ...interface{}) {
	n.messenger.sess.debugf("[negotiator] "+fmt, args...)
}

func (n *negotiator) handlePingPongMessage(b []byte, isPing bool) (err error) {
	defer func() { err = wrapError(err) }()
	n.debugf("handlePingPongMessage(b, %v)", isPing)
	if isPing {
		b[0] = 2
		_, err = n.messenger.WriteSingle(b)
		return
	}

	msg := &negotiationPingPongMessage{}
	err = n.parseMessage(msg, b)
	if err != nil {
		return
	}

	checkSum := sha512.Sum512(b[65:])
	if bytes.Compare(msg.Checksum[:], checkSum[:]) != 0 {
		n.debugf("invalid checksum on message of length %d: %v != %v",
			len(b), msg.Checksum, checkSum)
		err = newErrInvalidChecksum(msg.Checksum[:], checkSum[:])
		return
	}

	n.lockDo(func() {
		if uint32(len(b)) > n.localLargestRTT {
			n.localLargestRTT = uint32(len(b))
		}
	})
	n.recvChan <- negotiatorRecvItem{
		MessageSize: uint32(len(b)),
		IterationID: msg.IterationID,
	}
	n.sendControl(false)
	return nil
}

func (n *negotiator) handlePingMessage(b []byte) (err error) {
	return n.handlePingPongMessage(b, true)
}

func (n *negotiator) handlePongMessage(b []byte) (err error) {
	return n.handlePingPongMessage(b, false)
}

func (n *negotiator) Handle(b []byte) (err error) {
	if len(b) < 1 {
		return newErrTooShort(1, 0)
	}
	n.debugf("received a message of type %d and length %d", b[0], len(b))
	switch b[0] {
	case 0:
		return n.handleControlMessage(b)
	case 1:
		return n.handlePingMessage(b)
	case 2:
		return n.handlePongMessage(b)
	default:
		return newErrUnknownSubType(b[0])
	}
}

func (n *negotiator) Close() (err error) {
	n.debugf("Close()")
	defer func() { n.debugf("/Close(): err:%v", err) }()

	shouldSkip := false
	n.lockDo(func() {
		if n.cancelFn == nil {
			shouldSkip = true
			return
		}
		n.cancelFn()
		n.cancelFn = nil
	})
	if shouldSkip {
		return
	}

	err = n.messenger.Close()
	n.wgTasks.Wait()
	if n.recvChan == nil {
		return
	}
	close(n.recvChan)
	n.recvChan = nil
	return
}
