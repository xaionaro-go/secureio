package secureio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionBigWrite(t *testing.T) {
	ctx := context.Background()

	identity0, identity1, conn0, conn1 := testPair(t)

	sess0 := identity0.NewSession(ctx, identity1, conn0, &testLogger{"0", t, true, true, nil}, nil)
	sess1 := identity1.NewSession(ctx, identity0, conn1, &testLogger{"1", t, true, true, nil}, nil)

	writeBuf := make([]byte, maxPayloadSize)
	rand.Read(writeBuf)
	readBuf := make([]byte, maxPayloadSize)

	_, err := sess0.Write(writeBuf)
	assert.NoError(t, err)

	_, err = sess1.Read(readBuf)
	assert.NoError(t, err)

	assert.Equal(t, writeBuf, readBuf)

	assert.NoError(t, sess0.Close())
	assert.NoError(t, sess1.Close())

	sess0.WaitForClosure()
	sess1.WaitForClosure()

	assert.True(t, sess0.isDone())
	assert.True(t, sess1.isDone())
}

func TestSessionWaitForSendInfo(t *testing.T) {
	ctx := context.Background()

	identity0, identity1, conn0, conn1 := testPair(t)

	sess0 := identity0.NewSession(ctx, identity1, conn0, &testLogger{"0", t, true, true, nil}, nil)
	sess1 := identity1.NewSession(ctx, identity0, conn1, &testLogger{"1", t, true, true, nil}, nil)

	writeBuf := make([]byte, 8)
	rand.Read(writeBuf)
	readBuf := make([]byte, 8)

	sendInfo := sess0.WriteMessageAsync(MessageType_dataPacketType0, writeBuf)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		_, err := sess1.Read(readBuf)
		assert.NoError(t, err)

		wg.Done()
	}()

	<-sendInfo.C
	assert.NoError(t, sendInfo.Err)
	sendInfo.Release()

	wg.Wait()
	assert.Equal(t, writeBuf, readBuf)

	assert.NoError(t, sess0.Close())
	assert.NoError(t, sess1.Close())

	sess0.WaitForClosure()
	sess1.WaitForClosure()

	assert.True(t, sess0.isDone())
	assert.True(t, sess1.isDone())
}

func TestSessionAsyncWrite(t *testing.T) {
	ctx := context.Background()

	identity0, identity1, conn0, conn1 := testPair(t)

	sendLogger := &testLogger{"0", t, true, true, nil}
	sess0 := identity0.NewSession(ctx, identity1, conn0, sendLogger, nil)
	sess1 := identity1.NewSession(ctx, identity0, conn1, &testLogger{"1", t, true, true, nil}, nil)

	writeBuf := make([]byte, maxPayloadSize/4)
	rand.Read(writeBuf)
	readBuf := make([]byte, maxPayloadSize/4)

	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			sendInfo := sess0.WriteMessageAsync(MessageType_dataPacketType0, writeBuf)
			sendLogger.Debugf(`WAITING: sendInfo == %v`, sendInfo)
			<-sendInfo.C
			sendLogger.Debugf(`/WAITING: sendInfo == %v`, sendInfo)
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
	}

	wg.Wait()

	assert.NoError(t, sess0.Close())
	assert.NoError(t, sess1.Close())

	sess0.WaitForClosure()
	sess1.WaitForClosure()

	assert.True(t, sess0.isDone())
	assert.True(t, sess1.isDone())
}

func TestSession_WriteMessageAsync_noHanging(t *testing.T) {
	benchmarkSessionWriteRead(
		&testing.B{N: 10000},
		1, 0, true, false,
		&testLogger{"0", t, true, false, nil},
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
			if errors.Is(err, io.EOF) {
				return false
			}
			if pathErr := (*os.PathError)(nil); errors.As(err, &pathErr) {
				panic(fmt.Sprintf("%v: %v", pathErr.Path, pathErr.Err))
			}
			panic(err)
			return false
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
				case <-sendInfo.C:
				}
				if sendInfo.Err != nil {
					if errors.As(sendInfo.Err, &ErrAlreadyClosed{}) {
						panic(sendInfo.Err)
					}
				}
				sendInfo.Release()
			}
		}()

		sess1.SetHandlerFuncs(MessageType_dataPacketType0,
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
					MessageType_dataPacketType0,
					writeBuf,
				)
			} else {
				sendInfo = sess0.WriteMessageAsync(
					MessageType_dataPacketType0,
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
