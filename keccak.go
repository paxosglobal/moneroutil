package moneroutil

import (
	"github.com/ebfe/keccak"
)

const (
	ChecksumLength = 4
	HashLength     = 32
)

type Hash [HashLength]byte
type Checksum [ChecksumLength]byte

func Keccak256(data ...[]byte) (result Hash) {
	h := keccak.New256()
	for _, b := range data {
		h.Write(b)
	}
	r := h.Sum(nil)
	copy(result[:], r)
	return
}

func GetChecksum(data ...[]byte) (result Checksum) {
	keccak256 := Keccak256(data...)
	copy(result[:], keccak256[:4])
	return
}

func Keccak512(data ...[]byte) (result Hash) {
	h := keccak.New512()
	for _, b := range data {
		h.Write(b)
	}
	r := h.Sum(nil)
	copy(result[:], r)
	return
}
