package secureio

import (
	"math/bits"

	xerrors "github.com/xaionaro-go/errors"
)

//go:nosplit
func pendingChainIsSetSet(oldValue, addValue uint64) (uint64, int) {
	newValue := oldValue | addValue
	diff := newValue ^ oldValue
	return newValue, bits.OnesCount64(diff)
}

//go:nosplit
func setLeadingOnes64(v int) uint64 {
	switch v {
	case 0:
		return 0x0000000000000000
	case 1:
		return 0x8000000000000000
	case 2:
		return 0xc000000000000000
	case 3:
		return 0xe000000000000000
	case 4:
		return 0xf000000000000000
	case 5:
		return 0xf800000000000000
	case 6:
		return 0xfc00000000000000
	case 7:
		return 0xfe00000000000000
	case 8:
		return 0xff00000000000000
	case 9:
		return 0xff80000000000000
	case 10:
		return 0xffc0000000000000
	case 11:
		return 0xffe0000000000000
	case 12:
		return 0xfff0000000000000
	case 13:
		return 0xfff8000000000000
	case 14:
		return 0xfffc000000000000
	case 15:
		return 0xfffe000000000000
	case 16:
		return 0xffff000000000000
	case 17:
		return 0xffff800000000000
	case 18:
		return 0xffffc00000000000
	case 19:
		return 0xffffe00000000000
	case 20:
		return 0xfffff00000000000
	case 21:
		return 0xfffff80000000000
	case 22:
		return 0xfffffc0000000000
	case 23:
		return 0xfffffe0000000000
	case 24:
		return 0xffffff0000000000
	case 25:
		return 0xffffff8000000000
	case 26:
		return 0xffffffc000000000
	case 27:
		return 0xffffffe000000000
	case 28:
		return 0xfffffff000000000
	case 29:
		return 0xfffffff800000000
	case 30:
		return 0xfffffffc00000000
	case 31:
		return 0xfffffffe00000000
	case 32:
		return 0xffffffff00000000
	case 33:
		return 0xffffffff80000000
	case 34:
		return 0xffffffffc0000000
	case 35:
		return 0xffffffffe0000000
	case 36:
		return 0xfffffffff0000000
	case 37:
		return 0xfffffffff8000000
	case 38:
		return 0xfffffffffc000000
	case 39:
		return 0xfffffffffe000000
	case 40:
		return 0xffffffffff000000
	case 41:
		return 0xffffffffff800000
	case 42:
		return 0xffffffffffc00000
	case 43:
		return 0xffffffffffe00000
	case 44:
		return 0xfffffffffff00000
	case 45:
		return 0xfffffffffff80000
	case 46:
		return 0xfffffffffffc0000
	case 47:
		return 0xfffffffffffe0000
	case 48:
		return 0xffffffffffff0000
	case 49:
		return 0xffffffffffff8000
	case 50:
		return 0xffffffffffffc000
	case 51:
		return 0xffffffffffffe000
	case 52:
		return 0xfffffffffffff000
	case 53:
		return 0xfffffffffffff800
	case 54:
		return 0xfffffffffffffc00
	case 55:
		return 0xfffffffffffffe00
	case 56:
		return 0xffffffffffffff00
	case 57:
		return 0xffffffffffffff80
	case 58:
		return 0xffffffffffffffc0
	case 59:
		return 0xffffffffffffffe0
	case 60:
		return 0xfffffffffffffff0
	case 61:
		return 0xfffffffffffffff8
	case 62:
		return 0xfffffffffffffffc
	case 63:
		return 0xfffffffffffffffe
	default:
		return 0xffffffffffffffff
	}
}

type pendingChain struct {
	IsSet    []uint64
	Data     []byte
	Expected uint64
	Received uint64
}

//go:nosplit
func (chain *pendingChain) Reset() {
	chain.Expected = 0
	chain.Received = 0
	for idx := range chain.IsSet {
		chain.IsSet[idx] = 0
	}
}

//go:nosplit
func (chain *pendingChain) Init(expectedLength uint64) {
	chain.Reset()
	chain.Expected = expectedLength
	if uint64(len(chain.Data)) >= expectedLength {
		return
	}
	chain.Data = make([]byte, expectedLength)
	chain.IsSet = make([]uint64, (expectedLength+63)/64)
}

//go:nosplit
func (chain *pendingChain) Merge(
	fragmentHdr *messageFragmentHeadersData,
	b []byte,
) ([]byte, error) {
	if chain.Received >= chain.Expected {
		return nil, xerrors.Errorf("already processed this chain, a packet duplication?")
	}

	lastPos := uint64(len(b)) + fragmentHdr.StartPos
	if lastPos > chain.Expected {
		return nil, newErrOutOfRange(chain.Expected, lastPos)
	}

	pos := fragmentHdr.StartPos
	copy(chain.Data[pos:], b)

	var newBytes uint64
	endPos := pos + uint64(len(b))
	isSet := chain.IsSet
	isSetPos := pos >> 6
	batchSetEndPos := endPos >> 6
	for ; isSetPos < batchSetEndPos; isSetPos++ {
		var newBytesLocal int
		isSet[isSetPos], newBytesLocal = pendingChainIsSetSet(isSet[isSetPos], 0xffffffffffffffff)
		newBytes += uint64(newBytesLocal)
	}
	pos = endPos & 0xffffffffffffffc0

	if pos < endPos {
		var newBytesLocal int
		isSetValue := setLeadingOnes64(int(endPos - pos))
		isSet[isSetPos], newBytesLocal = pendingChainIsSetSet(isSet[isSetPos], isSetValue)
		newBytes += uint64(newBytesLocal)
	}

	chain.Received += newBytes
	if chain.Received >= chain.Expected {
		return chain.Data, nil
	}
	return nil, nil
}
