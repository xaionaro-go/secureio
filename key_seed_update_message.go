package secureio

import (
	"unsafe"
)

type keySeedUpdateMessage struct {
	PublicKey [PublicKeySize]byte
	Signature [keySignatureSize]byte
}

var (
	keySeedUpdateMessageSize = int64(unsafe.Sizeof(keySeedUpdateMessage{}))
)
