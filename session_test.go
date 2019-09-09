package secureio

import (
	"context"
	"io"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/xaionaro-go/errors"
)

func TestSession(t *testing.T) {
	ctx := context.Background()

	identity0, identity1, conn0, conn1 := testPair(t)

	sess0 := identity0.NewSession(ctx, identity1, conn0, &testLogger{"0", t, true, false, nil}, nil)
	sess1 := identity1.NewSession(ctx, identity0, conn1, &testLogger{"1", t, true, false, nil}, nil)

	writeBuf := make([]byte, 65536-messageHeadersSize)
	rand.Read(writeBuf)
	readBuf := make([]byte, 65536-messageHeadersSize)

	_, err := sess0.Write(writeBuf)
	assert.NoError(t, err)

	_, err = sess1.Read(readBuf)
	assert.NoError(t, err)

	assert.Equal(t, writeBuf, readBuf)

	assert.NoError(t, sess0.Close())
	assert.NoError(t, sess1.Close())

	assert.True(t, sess0.isDone())
	assert.True(t, sess1.isDone())
}

func BenchmarkSessionWriteRead1(b *testing.B) {
	benchmarkSessionWriteRead(b, 1)
}
func BenchmarkSessionWriteRead16(b *testing.B) {
	benchmarkSessionWriteRead(b, 16)
}
func BenchmarkSessionWriteRead1024(b *testing.B) {
	benchmarkSessionWriteRead(b, 1024)
}
func BenchmarkSessionWriteRead65000(b *testing.B) {
	benchmarkSessionWriteRead(b, 65000)
}
func benchmarkSessionWriteRead(b *testing.B, blockSize uint) {
	ctx := context.Background()

	identity0, identity1, conn0, conn1 := testPair(nil)

	eventHandler := wrapErrorHandler(&dummyEventHandler{}, func(sess *Session, err error) {
		xerr := err.(*errors.Error)
		if xerr.Has(io.EOF) {
			return
		}
		panic(xerr)
	})

	sess0 := identity0.NewSession(ctx, identity1, conn0, eventHandler, nil)
	sess1 := identity1.NewSession(ctx, identity0, conn1, eventHandler, nil)
	defer sess0.Close()
	defer sess1.Close()

	writeBuf := make([]byte, blockSize)
	rand.Read(writeBuf)
	readBuf := make([]byte, blockSize)

	b.SetBytes(int64(blockSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := sess0.Write(writeBuf)
		if err != nil {
			panic(err)
		}
		_, err = sess1.Read(readBuf)
		if err != nil {
			panic(err)
		}
	}
}
