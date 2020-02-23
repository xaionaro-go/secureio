package secureio_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/xaionaro-go/slice"
	"github.com/xaionaro-go/unsafetools"

	. "github.com/xaionaro-go/secureio"
)

func TestSessionBigWrite(t *testing.T) {
	ctx := context.Background()

	identity0, identity1, conn0, conn1 := testPair(t)

	opts := &SessionOptions{
		OnInitFuncs: []OnInitFunc{func(sess *Session) {
			printLogsOfSession(t, true, sess)
		}},
		EnableDebug: true,
	}

	sess0 := identity0.NewSession(ctx, identity1, conn0, &testLogger{t, nil}, opts)
	sess1 := identity1.NewSession(ctx, identity0, conn1, &testLogger{t, nil}, opts)

	writeBuf := make([]byte, sess0.GetMaxPayloadSize())
	rand.Read(writeBuf)
	readBuf := make([]byte, sess0.GetMaxPayloadSize())

	_, err := sess0.Write(writeBuf)
	assert.NoError(t, err)

	_, err = sess1.Read(readBuf)
	assert.NoError(t, err)

	assert.Equal(t, writeBuf, readBuf)

	assert.NoError(t, sess0.Close())
	assert.NoError(t, sess1.Close())

	sess0.WaitForClosure()
	sess1.WaitForClosure()

	assert.Equal(t, SessionStateClosed, sess0.GetState())
	assert.Equal(t, SessionStateClosed, sess1.GetState())
}

func TestSessionWaitForSendInfo(t *testing.T) {
	ctx := context.Background()

	identity0, identity1, conn0, conn1 := testPair(t)

	opts := &SessionOptions{
		OnInitFuncs: []OnInitFunc{func(sess *Session) {
			printLogsOfSession(t, true, sess)
		}},
		EnableDebug: true,
	}

	sess0 := identity0.NewSession(ctx, identity1, conn0, &testLogger{t, nil}, opts)
	sess1 := identity1.NewSession(ctx, identity0, conn1, &testLogger{t, nil}, opts)

	writeBuf := make([]byte, 8)
	rand.Read(writeBuf)
	readBuf := make([]byte, 8)

	sendInfo := sess0.WriteMessageAsync(MessageTypeDataPacketType0, writeBuf)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		_, err := sess1.Read(readBuf)
		assert.NoError(t, err)

		wg.Done()
	}()

	<-sendInfo.Done()
	assert.NoError(t, sendInfo.Err)
	sendInfo.Release()

	wg.Wait()
	assert.Equal(t, writeBuf, readBuf)

	assert.NoError(t, sess0.Close())
	assert.NoError(t, sess1.Close())

	sess0.WaitForClosure()
	sess1.WaitForClosure()

	assert.Equal(t, SessionStateClosed, sess0.GetState())
	assert.Equal(t, SessionStateClosed, sess1.GetState())
}

func TestSessionAsyncWrite(t *testing.T) {
	ctx := context.Background()

	identity0, identity1, conn0, conn1 := testPair(t)

	sendLogger := &testLogger{t, nil}
	opts := &SessionOptions{
		OnInitFuncs: []OnInitFunc{func(sess *Session) {
			printLogsOfSession(t, true, sess)
		}},
		EnableDebug: true,
	}

	sess0 := identity0.NewSession(ctx, identity1, conn0, sendLogger, opts)
	sess1 := identity1.NewSession(ctx, identity0, conn1, &testLogger{t, nil}, opts)

	var wg sync.WaitGroup

	writeBuf := make([]byte, sess0.GetMaxPayloadSize()/4)
	rand.Read(writeBuf)

	for i := 0; i < 10; i++ {
		func() {
			readBuf := make([]byte, sess0.GetMaxPayloadSize()/4)

			wg.Add(1)
			go func() {
				sendInfo := sess0.WriteMessageAsync(MessageTypeDataPacketType0, writeBuf)
				<-sendInfo.Done()
				assert.NoError(t, sendInfo.Err)
				sendInfo.Release()
				wg.Done()
			}()

			wg.Add(1)
			go func() {
				_, err := sess1.Read(readBuf)
				assert.NoError(t, err)

				assert.Equal(t, writeBuf, readBuf)
				wg.Done()
			}()
		}()
	}

	wg.Wait()

	assert.NoError(t, sess0.Close())
	assert.NoError(t, sess1.Close())

	sess0.WaitForClosure()
	sess1.WaitForClosure()

	assert.Equal(t, SessionStateClosed, sess0.GetState())
	assert.Equal(t, SessionStateClosed, sess1.GetState())
}

func TestSession_WriteMessageAsync_noHanging(t *testing.T) {
	benchmarkSessionWriteRead(
		&testing.B{N: 10000},
		1, 0, true, false,
		&testLogger{t, nil},
	)
}

func BenchmarkSessionWriteRead1(b *testing.B) {
	benchmarkSessionWriteRead(b, 1, 0, false, true, nil)
}
func BenchmarkSessionWriteRead16(b *testing.B) {
	benchmarkSessionWriteRead(b, 16, 0, false, true, nil)
}
func BenchmarkSessionWriteRead1024(b *testing.B) {
	benchmarkSessionWriteRead(b, 1024, 0, false, true, nil)
}
func BenchmarkSessionWriteRead32000(b *testing.B) {
	benchmarkSessionWriteRead(b, 32000, 0, false, true, nil)
}
func BenchmarkSessionWriteRead64000(b *testing.B) {
	benchmarkSessionWriteRead(b, 64000, 0, false, true, nil)
}
func BenchmarkSessionWriteMessageAsyncRead1(b *testing.B) {
	benchmarkSessionWriteRead(b, 1, 0, true, false, nil)
}
func BenchmarkSessionWriteMessageAsyncRead16(b *testing.B) {
	benchmarkSessionWriteRead(b, 16, 0, true, false, nil)
}
func BenchmarkSessionWriteMessageAsyncRead1024(b *testing.B) {
	benchmarkSessionWriteRead(b, 1024, 0, true, false, nil)
}
func BenchmarkSessionWriteMessageAsyncRead32000(b *testing.B) {
	benchmarkSessionWriteRead(b, 32000, 0, true, false, nil)
}
func BenchmarkSessionWriteMessageAsyncRead64000(b *testing.B) {
	benchmarkSessionWriteRead(b, 64000, 0, true, false, nil)
}

func BenchmarkSessionWriteMessageAsyncRead1300_max1400(b *testing.B) {
	benchmarkSessionWriteRead(b, 1300, 1400, true, false, nil)
}

func benchmarkSessionWriteRead(
	b *testing.B,
	blockSize uint,
	maxPayloadSize uint,
	shouldWriteAsMessage bool,
	isSync bool,
	eventHandler EventHandler,
) {
	if !isSync && !shouldWriteAsMessage {
		panic(`!isSync && !shouldWriteAsMessage`)
	}

	b.ReportAllocs()

	ctx, cancelFunc := context.WithCancel(context.Background())

	identity0, identity1, conn0, conn1 := testPair(nil)

	if eventHandler == nil {
		eventHandler = wrapErrorHandler(&dummyEventHandler{}, func(sess *Session, err error) bool {
			if errors.Is(err, io.EOF) || errors.As(err, &ErrAlreadyClosed{}) {
				return false
			}
			if pathErr := (*os.PathError)(nil); errors.As(err, &pathErr) {
				panic(fmt.Sprintf("%v: %v", pathErr.Path, pathErr.Err))
			}
			panic(err)
			//return false
		})
	}

	var wg sync.WaitGroup

	var opts *SessionOptions
	if maxPayloadSize > 0 {
		opts = &SessionOptions{
			MaxPayloadSize: uint32(maxPayloadSize),
		}
	}

	sess0 := identity0.NewSession(ctx, identity1, conn0, eventHandler, opts)
	sess1 := identity1.NewSession(ctx, identity0, conn1, eventHandler, opts)
	defer func() {
		cancelFunc()
		sess0.Close()
		sess1.Close()
		conn0.Close()
		conn1.Close()
		sess0.WaitForClosure()
		sess1.WaitForClosure()
		wg.Wait()
		b.StopTimer()
	}()

	writeBuf := make([]byte, blockSize)
	rand.Read(writeBuf)
	readBuf := make([]byte, blockSize)

	b.SetBytes(int64(blockSize))

	sendInfoChan := make(chan *SendInfo, 10000)
	if !isSync {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancelFunc()
			for {
				var sendInfo *SendInfo
				select {
				case <-ctx.Done():
					return
				case sendInfo = <-sendInfoChan:
				}

				select {
				case <-ctx.Done():
					return
				case <-sendInfo.Done():
				}
				if sendInfo.Err != nil {
					if !errors.As(sendInfo.Err, &ErrAlreadyClosed{}) && !errors.As(sendInfo.Err, &ErrCanceled{}) {
						panic(sendInfo.Err)
					}
				}
				sendInfo.Release()
			}
		}()

		sess1.SetHandlerFuncs(MessageTypeDataPacketType0,
			nil,
			func(err error) {
				panic(err)
			},
		)
	}

	b.ResetTimer()

	var err error
	var sendInfo *SendInfo
	for i := 0; i < b.N; i++ {

		// write

		if shouldWriteAsMessage {
			if isSync {
				_, err = sess0.WriteMessage(
					MessageTypeDataPacketType0,
					writeBuf,
				)
			} else {
				sendInfo = sess0.WriteMessageAsync(
					MessageTypeDataPacketType0,
					writeBuf,
				)
			}
		} else {
			_, err = sess0.Write(writeBuf)
		}
		if err != nil {
			panic(err)
		}

		// read

		if isSync {
			_, err = sess1.Read(readBuf)
		} else {
			if shouldWriteAsMessage {
				sendInfoChan <- sendInfo
			} else {
				panic(`!isSync && !shouldWriteAsMessage`)
			}
		}
		if err != nil {
			panic(err)
		}
	}

	select {
	case <-ctx.Done():
		panic(`should not happened`)
	default:
	}
}

func TestHackerDuplicateMessage(t *testing.T) {
	ctx := context.Background()

	identity0, identity1, conn0, conn1 := testPair(t)

	opts := &SessionOptions{
		OnInitFuncs: []OnInitFunc{func(sess *Session) {
			printLogsOfSession(t, true, sess)
		}},
		EnableDebug: true,
		KeyExchangerOptions: KeyExchangerOptions{
			AnswersMode:   KeyExchangeAnswersModeDisable,
			RetryInterval: time.Millisecond,
		},
	}

	// No hacker, yet

	sess0 := identity0.NewSession(ctx, identity1, conn0, &testLogger{t, nil}, opts)
	sess1 := identity1.NewSession(ctx, identity0, conn1, &testLogger{t, nil}, opts)

	writeBuf := make([]byte, sess0.GetMaxPayloadSize())
	rand.Read(writeBuf)
	readBuf := make([]byte, sess0.GetMaxPayloadSize())

	// Now a hacker appears, listens a message in the middle a repeats it.
	// A secureio client should ignore the duplicate

	// Intercepting a message

	// wait for successful key-exchange
	sess0.WaitForState(ctx, SessionStateEstablished)
	sess1.WaitForState(ctx, SessionStateEstablished)

	// sess1.SetPause(true) will temporary pause sess1.
	// So we will be able to read from `conn1` to intercept a message.
	assert.NoError(t, sess1.SetPause(true))

	rand.Read(writeBuf)

	// Now sess1 is paused (does not listen for traffic
	// and now we can intercept it), so sending a message:
	_, err := sess0.Write(writeBuf)
	assert.NoError(t, err)

	// And intercepting it:
	interceptedMessage := make([]byte, sess1.GetMaxPacketSize()+1)
	n, err := conn1.Read(interceptedMessage)
	assert.Less(t, n, int(sess1.GetMaxPacketSize())+1)
	assert.NoError(t, err)

	// Unpausing and resending the message to pretend like we
	// weren't here:
	assert.Nil(t, sess1.SetPause(false))
	_, err = conn0.Write(interceptedMessage)
	assert.NoError(t, err)

	_, err = sess1.Read(readBuf)
	assert.NoError(t, err)

	assert.Equal(t, writeBuf, readBuf)

	// And now repeating the message (making a duplicate).
	// This message should be ignored by "sess1" (if everything
	// works correctly and option AllowReorderingAndDuplication
	// is off):
	_, err = conn0.Write(interceptedMessage)
	assert.NoError(t, err)

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()
		slice.SetZeros(readBuf)
		_, err = sess1.Read(readBuf)
		assert.NoError(t, err)

		if !assert.Equal(t, uint64(1), sess1.GetUnexpectedPacketIDCount()) {
			// Unblocking the goroutine below (with `runtime.Gosched()`)
			// if required.
			*unsafetools.FieldByName(sess1, `unexpectedPacketIDCount`).(*uint64) = 1
		}
	}()

	successfullyIgnoredTheDuplicate := false
	assert.Equal(t, uint64(0), sess1.GetUnexpectedPacketIDCount())
	go func() {
		for sess1.GetUnexpectedPacketIDCount() == 0 {
			runtime.Gosched()
		}
		successfullyIgnoredTheDuplicate = true

		// Just sending some message to unblock a goroutine above
		// (with `sess1.Read()`).
		_, err := sess0.Write([]byte{})
		assert.NoError(t, err)
	}()

	wg.Wait()
	assert.True(t, successfullyIgnoredTheDuplicate)

	// Disabling the defensive mechanism and trying again,
	// now we should receive the duplicate:
	unsafetools.FieldByName(sess1, `options`).(*SessionOptions).AllowReorderingAndDuplication = true

	_, err = conn0.Write(interceptedMessage)
	assert.NoError(t, err)

	slice.SetZeros(readBuf)
	_, err = sess1.Read(readBuf)
	assert.NoError(t, err)

	assert.Equal(t, writeBuf, readBuf)

	// The test is passed, closing...

	assert.NoError(t, sess0.Close())
	assert.NoError(t, sess1.Close())

	sess0.WaitForClosure()
	sess1.WaitForClosure()

	assert.Equal(t, SessionStateClosed, sess0.GetState())
	assert.Equal(t, SessionStateClosed, sess1.GetState())
}
