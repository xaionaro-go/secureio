package secureio

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/xaionaro-go/rand/mathrand"
)

func newXorShiftPRNG() *mathrand.PRNG {
	var seedBytes [8]byte
	_, err := rand.Read(seedBytes[:])
	if err != nil {
		panic(err)
	}
	seed := binary.LittleEndian.Uint64(seedBytes[:])

	return mathrand.NewWithSeed(seed)
}
