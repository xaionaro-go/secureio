package secureio

import (
	"github.com/aead/chacha20"
	"github.com/xaionaro-go/slice"
)

var (
	emptyIV = make([]byte, 24)
)

func decrypt(key []byte, iv []byte, dst, src []byte) {
	slice.SetZeros(dst)
	chacha20.XORKeyStream(dst, src, iv, key)
}

func encrypt(key []byte, iv []byte, dst, src []byte) {
	slice.SetZeros(dst)
	chacha20.XORKeyStream(dst, src, iv, key)
}
