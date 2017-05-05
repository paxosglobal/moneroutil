package moneroutil

import (
	"encoding/hex"
)

func HexToBytes(h string) (result [32]byte) {
	byteSlice, _ := hex.DecodeString(h)
	copy(result[:], byteSlice)
	return
}
