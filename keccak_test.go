package moneroutil

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestKeccak256(t *testing.T) {
	tests := []struct {
		name       string
		messageHex string
		wantHex    string
	}{
		{
			name:       "from monero 1",
			messageHex: "c8fedd380dbae40ffb52",
			wantHex:    "8e41962058b7422e7404253121489a3e63d186ed115086919a75105661483ba9",
		},
		{
			name:       "from monero 2",
			messageHex: "5020c4d530b6ec6cb4d9",
			wantHex:    "8a597f11961935e32e0adeab2ce48b3df2d907c9b26619dad22f42ff65ab7593",
		},
		{
			name:       "from monero cryptotest.pl",
			messageHex: "0f3fe9c20b24a11bf4d6d1acd335c6a80543f1f0380590d7323caf1390c78e88",
			wantHex:    "73b7a236f2a97c4e1805f7a319f1283e3276598567757186c526caf9a49e0a92",
		},
	}
	for _, test := range tests {
		message, _ := hex.DecodeString(test.messageHex)
		got := Keccak256(message)
		want := HexToBytes(test.wantHex)
		if bytes.Compare(want[:], got[:]) != 0 {
			t.Errorf("want %x, got %x", want, got)
		}
	}
}
