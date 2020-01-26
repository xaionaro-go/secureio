package secureio

import (
	"crypto/cipher"

	"github.com/xaionaro-go/slice"
)

func decrypt(cipherInstance cipher.Block, iv []byte, dst, src []byte) {
	stream := cipher.NewCTR(cipherInstance, iv)
	slice.SetZeros(dst)
	stream.XORKeyStream(dst, src)
}

func encrypt(cipherInstance cipher.Block, iv []byte, dst, src []byte) {
	decrypt(cipherInstance, iv, dst, src)
}
