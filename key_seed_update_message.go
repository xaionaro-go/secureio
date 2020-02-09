package secureio

type keySeedUpdateMessage struct {
	PublicKey [curve25519PublicKeySize]byte
	Signature [keySignatureSize]byte
}
