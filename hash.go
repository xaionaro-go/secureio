package secureio

import (
	"golang.org/x/crypto/sha3"

	"lukechampine.com/blake3"
)

// hash hashes the values using blake3 and sha3.
// For each hashing it adds all the salts.
func hash(input []byte, salts ...[]byte) []byte {
	inputs := append([][]byte{input}, salts...)
	totalLength := 0
	for _, input := range inputs {
		totalLength += len(input)
	}
	preHashInput := make([]byte, 0, totalLength)
	for _, input := range inputs {
		preHashInput = append(preHashInput, input...)
	}
	preHash := blake3.Sum256(preHashInput)
	hashInput := make([]byte, 0, len(preHash)+totalLength-len(input))
	hashInput = append(hashInput, preHash[:]...)
	for _, salt := range salts {
		hashInput = append(hashInput, salt...)
	}
	hash := sha3.Sum256(hashInput)
	return hash[:]
}
