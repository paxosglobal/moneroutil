package moneroutil

import (
	"encoding/hex"
)

func HexToKey(h string) (result Key) {
	byteSlice, _ := hex.DecodeString(h)
	copy(result[:], byteSlice)
	return
}

func HexToHash(h string) (result Hash) {
	byteSlice, _ := hex.DecodeString(h)
	copy(result[:], byteSlice)
	return
}
