package secureio

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkSetLeadingOnes(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		setLeadingOnes64(int(uint8(i)))
	}
}

func BenchmarkPendingChainIsSet_Set(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pendingChainIsSetSet(0x123456789abcdef, uint64(i))
	}
}

func BenchmarkPendingChain_Merge(b *testing.B) {
	var chain pendingChain
	var fragmentHdr messageFragmentHeadersData
	for _, size := range []uint64{1, 1000, 10000} {
		b.Run(fmt.Sprintf("size%d", size), func(b *testing.B) {
			data := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				chain.Init(60000)
				for pos := uint64(0); pos < 60000; pos += size {
					fragmentHdr.StartPos = pos
					_, _ = chain.Merge(&fragmentHdr, data)
				}
			}
		})
	}
}

func TestPendingChain_Merge(t *testing.T) {
	data := make([]byte, 65536)

	rand.Seed(0)
	for i := 0; i < 1000; i++ {
		totalLength := 1 + rand.Uint64()%65536
		var chain pendingChain
		var fragmentHdr messageFragmentHeadersData
		chain.Init(totalLength)
		fragmentLength := 1 + rand.Uint64()%totalLength
		data = data[:totalLength]
		rand.Read(data)
		for pos := uint64(0); pos < totalLength; pos += fragmentLength {
			fragmentHdr.StartPos = pos
			dataCmp, err := chain.Merge(&fragmentHdr, data[pos:u64min(pos+fragmentLength, totalLength)])
			require.NoError(t, err)
			if dataCmp != nil {
				require.True(t, pos+fragmentLength >= totalLength, fmt.Sprint(pos, fragmentLength, totalLength))
				require.True(t, bytes.Compare(data, dataCmp) == 0)
			}
		}
	}
}
