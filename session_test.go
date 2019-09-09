package secureio

import (
	"context"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSession(t *testing.T) {
	ctx := context.Background()

	identity0, identity1, conn0, conn1 := testPair(t)

	sess0 := identity0.NewSession(ctx, identity1, conn0, &testLogger{"0", t, true, nil}, nil)
	sess1 := identity1.NewSession(ctx, identity0, conn1, &testLogger{"1", t, true, nil}, nil)

	writeBuf := make([]byte, 65536-messageHeadersSize)
	rand.Read(writeBuf)
	readBuf := make([]byte, 65536-messageHeadersSize)

	_, err := sess0.Write(writeBuf)
	assert.NoError(t, err)

	_, err = sess1.Read(readBuf)
	assert.NoError(t, err)

	assert.Equal(t, writeBuf, readBuf)
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

	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	identity0, identity1, conn0, conn1 := testPair(nil)

	eventHandler := wrapErrorHandler(&dummyEventHandler{}, func(sess *Session, err error) {
		panic(err)
	})

	sess0 := identity0.NewSession(ctx, identity1, conn0, eventHandler, nil)
	sess1 := identity1.NewSession(ctx, identity0, conn1, eventHandler, nil)

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
