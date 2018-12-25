package cryptofilter

import (
	"io"
)

type keyExchanger struct {
}

func newKeyExchanger(readWriter io.ReadWriter, okFunc func([]byte), errFunc func(error)) *keyExchanger {
	return nil
}
