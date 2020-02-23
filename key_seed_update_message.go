package secureio

import (
	"encoding/binary"
)

var (
	keySeedUpdateMessageContainerSize = binary.Size(keySeedUpdateMessageContainer{})
	keySeedUpdateMessageSignedSize    = binary.Size(keySeedUpdateMessageSigned{})
)

type keySeedUpdateMessageContainer struct {
	KeyID uint64
	keySeedUpdateMessageSigned
}

type keySeedUpdateMessageSigned struct {
	Signature [keySignatureSize]byte
	keySeedUpdateMessage
}

type keySeedUpdateMessage struct {
	SessionID   SessionID
	PublicKey   [curve25519PublicKeySize]byte
	AnswersMode KeyExchangeAnswersMode
	Flags       keySeedUpdateMessageFlags
}

type keySeedUpdateMessageFlags uint8

const (
	keySeedUpdateMessageFlagsIsAnswer = keySeedUpdateMessageFlags(1 << iota)
)

func (flags keySeedUpdateMessageFlags) IsAnswer() bool {
	return flags&keySeedUpdateMessageFlagsIsAnswer != 0
}

func (flags *keySeedUpdateMessageFlags) SetIsAnswer(v bool) {
	if v {
		*flags |= keySeedUpdateMessageFlagsIsAnswer
	} else {
		*flags &= ^keySeedUpdateMessageFlagsIsAnswer
	}
}
