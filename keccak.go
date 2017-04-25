package moneroutil

import (
	"github.com/ebfe/keccak"
)

func Keccak256(data ...[]byte) (result []byte) {
	h := keccak.New256()
	for _, b := range data {
		h.Write(b)
	}
	result = h.Sum(nil)
	return
}

func Checksum(data ...[]byte) (result []byte) {
	keccak256 := Keccak256(data...)
	result = keccak256[:4]
	return
}
