package secureio

type keySeedUpdateMessage struct {
	PublicKey   [curve25519PublicKeySize]byte
	Signature   [keySignatureSize]byte
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
