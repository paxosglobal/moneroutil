package moneroutil

import (
	"bytes"
)

func ReadVarInt(buf *bytes.Buffer) (result uint64, err error) {
	var b byte
	for i := 0; ; i++ {
		b, err = buf.ReadByte()
		if err != nil {
			return
		}
		result += (uint64(b) & 0x7f) << uint(i*7)
		if uint64(b)&0x80 == 0 {
			break
		}
	}
	return
}

func Uint64ToBytes(num uint64) (result []byte) {
	for ; num >= 0x80; num >>= 7 {
		result = append(result, byte((num&0x7f)|0x80))
	}
	result = append(result, byte(num))
	return
}
