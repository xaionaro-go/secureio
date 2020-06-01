package secureio

type negotiationControlMessage struct {
	MessageSubType uint8 // should be always 0
	LargestRTT     uint32
	Flags          negotiationMessageFlags
}

type negotiationMessageFlags uint8

const (
	negotiationMessageFlagIsNegotiationEnd = negotiationMessageFlags(1 << iota)
)

func (flags *negotiationMessageFlags) SetIsNegotiationEnd(isNegotiationEnd bool) {
	if isNegotiationEnd {
		*flags |= negotiationMessageFlagIsNegotiationEnd
	} else {
		*flags &= ^negotiationMessageFlagIsNegotiationEnd
	}
}

func (flags negotiationMessageFlags) IsNegotiationEnd() bool {
	return flags&negotiationMessageFlagIsNegotiationEnd != 0
}

type negotiationPingPongMessage struct {
	MessageSubType uint8 // should be always "1" for "ping" and "2" for "pong"

	// Checksum is the checksum of the payload follows after this headers.
	//
	// Despite the fact there actually no need for cryptographic hash
	// function, we use sha512 anyway. There's no need in performance
	// for this procedure, while cryptographic functions are more stable
	// against random collisions, so why not?
	Checksum [64]byte

	IterationID uint32

	// ... the payload follows here...
}
