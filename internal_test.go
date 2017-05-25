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

// RandomPubKey takes a random scalar, interprets it as a point on the curve
// and then multiplies by 8 to make it a point in the Group
func RandomPubKey() (result *Key) {
	result = new(Key)
	p3 := new(ExtendedGroupElement)
	var p1 ProjectiveGroupElement
	var p2 CompletedGroupElement
	h := RandomScalar()
	p1.FromBytes(h)
	GeMul8(&p2, &p1)
	p2.ToExtended(p3)
	p3.ToBytes(result)
	return
}
