package moneroutil

func ReadVarInt(varInt []byte) (result int64) {
	for i, b := range varInt {
		result += (int64(b) & 0x7f) << uint(i*7)
		if int64(b)&0x80 == 0 {
			break
		}
	}
	return
}

func WriteVarInt(num int64) (result []byte) {
	for ; num >= 0x80; num >>= 7 {
		result = append(result, byte((num&0x7f)|0x80))
	}
	result = append(result, byte(num))
	return
}
