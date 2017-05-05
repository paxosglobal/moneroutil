package moneroutil

import (
	"bytes"
)

type Address struct {
	network     int
	spendingKey []byte
	viewingKey  []byte
}

func (a *Address) Base58() (result string) {
	prefix := []byte{byte(a.network)}
	checksum := GetChecksum(prefix, a.spendingKey, a.viewingKey)
	result = EncodeMoneroBase58(prefix, a.spendingKey, a.viewingKey, checksum[:])
	return
}

func NewAddress(address string) (result *Address, err string) {
	raw := DecodeMoneroBase58(address)
	if len(raw) != 69 {
		err = "Address is the wrong length"
		return
	}
	checksum := GetChecksum(raw[:65])
	if bytes.Compare(checksum[:], raw[65:]) != 0 {
		err = "Checksum does not validate"
		return
	}
	result = &Address{
		network:     int(raw[0]),
		spendingKey: raw[1:33],
		viewingKey:  raw[33:65],
	}
	return
}
