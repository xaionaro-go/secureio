package secureio

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPacketIDStorage_shiftValue(t *testing.T) {
	r := rand.New(rand.NewSource(0))
	v0 := r.Uint64()
	v1 := r.Uint64()
	stor := newPacketIDStorage(128)
	stor.table[0] = v0
	stor.table[1] = v1
	stor.shiftValue(31)
	assert.Equal(t, v0<<31, stor.table[0])
	assert.Equal(t, (v0>>33)|(v1<<31), stor.table[1])
}

func TestPacketIDStorage_getAtOffset(t *testing.T) {
	stor := newPacketIDStorage(128)
	stor.table[1] = 8
	assert.Equal(t, false, stor.getAtOffset(66))
	assert.Equal(t, true, stor.getAtOffset(67))
	assert.Equal(t, false, stor.getAtOffset(68))
}

func TestPacketIDStorage_setAtOffset(t *testing.T) {
	stor := newPacketIDStorage(128)
	stor.setAtOffset(67, true)
	assert.Equal(t, uint64(0), stor.table[0])
	assert.Equal(t, uint64(8), stor.table[1])
	stor.setAtOffset(67, false)
	assert.Equal(t, uint64(0), stor.table[1])
}

func TestPacketIDStorage_Push(t *testing.T) {
	for _, storSize := range []uint{0, 64, 128} {
		stor := newPacketIDStorage(storSize)
		assert.True(t, stor.Push(1), storSize)
		assert.True(t, stor.Push(2), storSize)
		assert.False(t, stor.Push(2), storSize)
		assert.False(t, stor.Push(1), storSize)
		assert.True(t, stor.Push(3), storSize)
		assert.False(t, stor.Push(1), storSize)
		if storSize == 0 {
			continue
		}
		assert.True(t, stor.Push(uint64(storSize)), storSize)
		assert.True(t, stor.Push(uint64(storSize)-1), storSize)
		assert.True(t, stor.Push(uint64(storSize)-2), storSize)
		assert.True(t, stor.Push(4), storSize)
		assert.True(t, stor.Push(uint64(storSize+1)), storSize)
		assert.False(t, stor.Push(uint64(storSize)), storSize)
		assert.False(t, stor.Push(uint64(storSize)-1), storSize)
		assert.False(t, stor.Push(uint64(storSize)-2), storSize)
		assert.False(t, stor.Push(4), storSize)
		assert.False(t, stor.Push(1), storSize)

		// randomValid-test:
		s := make([]uint64, storSize)
		stor = newPacketIDStorage(storSize)
		for idx := 0; idx < int(storSize); idx++ {
			s[idx] = uint64(idx)
		}
		for idx := 0; idx < int(storSize); idx += int(storSize) {
			blockSize := min(int(storSize), int(storSize)-idx)
			rand.Shuffle(blockSize, func(i, j int) {
				s[idx+i], s[idx+j] = s[idx+j], s[idx+i]
			})
		}
		for idx := 0; idx < int(storSize); idx++ {
			assert.True(t, stor.Push(s[idx]), fmt.Sprint(storSize, idx))
		}
	}
}

func BenchmarkPacketIDStorage_Push(b *testing.B) {
	for _, testName := range []string{"forward", "backward", "randomValid", "invalid"} {
		b.Run(testName, func(b *testing.B) {
			for _, storSize := range []uint{0, 64, 128, 256, 512, 1024, 1024 * 4, 1024 * 16, 1024 * 64, 1024 * 256, 1024 * 1024} {
				if storSize == 0 && testName != "forward" {
					continue
				}
				b.Run(fmt.Sprintf("storSize%d", storSize), func(b *testing.B) {
					stor := newPacketIDStorage(storSize)
					s := make([]uint64, b.N)
					switch testName {
					case "forward":
						for idx := 0; idx < b.N; idx++ {
							s[idx] = uint64(idx)
						}
					case "backward":
						for idx := 0; idx < b.N; {
							blockSize := min(int(storSize), b.N-idx)
							for i := 0; i < blockSize; i++ {
								s[idx+blockSize-i-1] = uint64(idx)
							}
							idx += int(storSize)
						}
					case "randomValid":
						for idx := 0; idx < b.N; idx++ {
							s[idx] = uint64(idx)
						}
						for idx := 0; idx < b.N; idx += int(storSize) {
							blockSize := min(int(storSize), b.N-idx)
							rand.Shuffle(blockSize, func(i, j int) {
								s[idx+i], s[idx+j] = s[idx+j], s[idx+i]
							})
						}
					case "invalid":
						s[0] = uint64(storSize + 1)
					}
					b.ResetTimer()
					for idx := 0; idx < b.N; idx++ {
						stor.Push(s[idx])
					}
				})
			}
		})
	}
}
