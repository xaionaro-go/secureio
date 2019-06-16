package secureio

import (
	"unsafe"
)

type keySeedUpdateMessage struct {
	PublicKey [PublicKeySize]byte
	Signature [KeySignatureSize]byte
}

var (
	keySeedUpdateMessageSize = int64(unsafe.Sizeof(keySeedUpdateMessage{}))
)
