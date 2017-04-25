package moneroutil

import (
	"bytes"
	"testing"
)

func TestVarInt(t *testing.T) {
	tests := []struct {
		name   string
		varInt []byte
		want   int64
	}{
		{
			name:   "1 byte",
			varInt: []byte{0x01},
			want:   1,
		},
		{
			name:   "3 bytes",
			varInt: []byte{0x8f, 0xd6, 0x17},
			want:   387855,
		},
		{
			name:   "4 bytes",
			varInt: []byte{0x80, 0x92, 0xf4, 0x01},
			want:   4000000,
		},
		{
			name:   "7 bytes",
			varInt: []byte{0x80, 0xc0, 0xca, 0xf3, 0x84, 0xa3, 0x02},
			want:   10000000000000,
		},
	}
	var got int64
	var gotVarInt []byte
	for _, test := range tests {
		gotVarInt = WriteVarInt(test.want)
		if bytes.Compare(gotVarInt, test.varInt) != 0 {
			t.Errorf("%s: varint want %x, got %x", test.name, test.varInt, gotVarInt)
			continue
		}
		got = ReadVarInt(test.varInt)
		if test.want != got {
			t.Errorf("%s: want %d, got %d", test.name, test.want, got)
			continue
		}
	}
}
