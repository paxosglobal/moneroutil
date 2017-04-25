package moneroutil

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAddressError(t *testing.T) {
	_, err := NewAddress("")
	want := "Address is the wrong length"
	if err != want {
		t.Errorf("want: %s, got: %s", want, err)
	}
	_, err = NewAddress("46w3n5EGhBeZkYmKvQRsd8UK9GhvcbYWQDobJape3NLMMFEjFZnJ3CnRmeKspubQGiP8iMTwFEX2QiBsjUkjKT4SSPd3fK1")
	want = "Checksum does not validate"
	if err != want {
		t.Errorf("want: %s, got: %s", want, err)
	}
}

func TestAddress(t *testing.T) {
	tests := []struct {
		name           string
		network        int
		spendingKeyHex string
		viewingKeyHex  string
		address        string
	}{
		{
			name:           "generic",
			network:        MainNetwork,
			spendingKeyHex: "8c1a9d5ff5aaf1c3cdeb2a1be62f07a34ae6b15fe47a254c8bc240f348271679",
			viewingKeyHex:  "0a29b163e392eb9416a52907fd7d3b84530f8d02ff70b1f63e72fdcb54cf7fe1",
			address:        "46w3n5EGhBeZkYmKvQRsd8UK9GhvcbYWQDobJape3NLMMFEjFZnJ3CnRmeKspubQGiP8iMTwFEX2QiBsjUkjKT4SSPd3fKp",
		},
		{
			name:           "generic 2",
			network:        MainNetwork,
			spendingKeyHex: "5007b84275af9a173c2080683afce90b2157ab640c18ddd5ce3e060a18a9ce99",
			viewingKeyHex:  "27024b45150037b677418fcf11ba9675494ffdf994f329b9f7a8f8402b7934a0",
			address:        "44f1Y84r9Lu4tQdLWRxV122rygfhUeVBrcmBaqcYCwUHScmf1ht8DFLXX9YN4T7nPPLcpqYLUdrFiY77nQYeH9RuK9gg4p6",
		},
		{
			name:           "require 1 padding in middle",
			network:        MainNetwork,
			spendingKeyHex: "6add197bd82866e8bfbf1dc2fdf49873ec5f679059652da549cd806f2b166756",
			viewingKeyHex:  "f5cf2897088fda0f7ac1c42491ed7d558a46ee41d0c81d038fd53ff4360afda0",
			address:        "45fzHekTd5FfvxWBPYX2TqLPbtWjaofxYUeWCi6BRQXYFYd85sY2qw73bAuKhqY7deFJr6pN3STY81bZ9x2Zf4nGKASksqe",
		},
		{
			name:           "require 1 padding in last chunk",
			network:        MainNetwork,
			spendingKeyHex: "50defe92d88b19aaf6bf66f061dd4380b79866a4122b25a03bceb571767dbe7b",
			viewingKeyHex:  "f8f6f28283921bf5a17f0bcf4306233fc25ce9b6276154ad0de22aebc5c67702",
			address:        "44grjkXtDHJVbZgtU1UKnrNXidcHfZ3HWToU5WjR3KgHMjgwrYLjXC6i5vm3HCp4vnBfYaNEyNiuZVwqtHD2SenS1JBRyco",
		},
		{
			name:           "testnet",
			network:        TestNetwork,
			spendingKeyHex: "8de9cce254e60cd940abf6c77ef344c3a21fad74320e45734fbfcd5870e5c875",
			viewingKeyHex:  "27024b45150037b677418fcf11ba9675494ffdf994f329b9f7a8f8402b7934a0",
			address:        "9xYZvCDf6aFdLd7Qawg5XHZitWLKoeFvcLHfe5GxsGCFLbXSWeQNKciXX9YN4T7nPPLcpqYLUdrFiY77nQYeH9RuK9bogZJ",
		},
	}
	var base58 string
	var spendingKey, viewingKey []byte
	for _, test := range tests {
		spendingKey, _ = hex.DecodeString(test.spendingKeyHex)
		viewingKey, _ = hex.DecodeString(test.viewingKeyHex)
		address, _ := NewAddress(test.address)
		if address.network != test.network {
			t.Errorf("%s: want: %d, got: %d", test.name, test.network, address.network)
			continue
		}
		if bytes.Compare(address.spendingKey, spendingKey) != 0 {
			t.Errorf("%s: want: %x, got: %x", test.name, spendingKey, address.spendingKey)
			continue
		}
		if bytes.Compare(address.viewingKey, viewingKey) != 0 {
			t.Errorf("%s: want: %x, got: %x", test.name, viewingKey, address.viewingKey)
			continue
		}
		base58 = address.Base58()
		if base58 != test.address {
			t.Errorf("%s: want: %s, got: %s", test.name, test.address, base58)
			continue
		}
	}
}
