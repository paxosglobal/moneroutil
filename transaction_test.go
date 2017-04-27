package moneroutil

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestTransactionParse(t *testing.T) {

	serializedTxHex := "014b01ff0f098fd61702a3ef0df2a51b14891676b39f18d6c0b8c52bfc3f6ba5f63f792e993f73b900df8092f40102204e4d5992876b76cc8a30760c8fd82dbaf948cb2d858278a08f4d8db326682a8087a70e027a2328c2d86a1f84335010d183d0eef067195da4a57169ac9d1c8c1f84ec74a580d293ad03023c6411e620104487402583db89dd15245448092f339a30a4982e076c7ba0a7578094ebdc0302861696af6e92cea973fa217f3b4df3e8c43a2a1cb888b515e23d2d5d3d41ba688088aca3cf0202d3087348abe2dffa189c79f82e032f14cbd12cfd6ece0a5192ec235a4cf2c96e8090cad2c60e02feb619b90856473e906295252cc9a87abbb7f5db409579d3169be5ee23b35ab680e08d84ddcb010275cd0dbe02a00558669ef424c2d5f8cbefc8c4af711f1afde0404628c401b13580c0caf384a30202b1bb2e13bf7c1d88885b7ebf2be56e5064af24d69f3c92d9264550122eed1a0b2101bbac13803d9b7941444cc817292b91a9634fa6cee88ced917571df2e0c87ad79"
	expectedHashHex := "e3a799da24d9f41aac231ba2efb853ae649283feaf5e1ba46b5fc2c194414c5d"
	serializedTx, _ := hex.DecodeString(serializedTxHex)
	expectedHash, _ := hex.DecodeString(expectedHashHex)
	hash := Keccak256(serializedTx)
	if bytes.Compare(expectedHash, hash) != 0 {
		t.Fatalf("want %x, got %x", expectedHash, hash)
	}
	buffer := new(bytes.Buffer)
	buffer.Write(serializedTx)
	transaction, err := ParseTransaction(buffer)
	if err != nil {
		t.Fatalf("error parsing tx: %s", err)
	}
	wantVersion := uint32(1)
	if wantVersion != transaction.version {
		t.Fatalf("version: want %d, got %d", wantVersion, transaction.version)
	}
	wantUnlock := uint64(75)
	if wantUnlock != transaction.unlockTime {
		t.Fatalf("unlock: want %d, got %d", wantUnlock, transaction.unlockTime)
	}
	wantSum := uint64(17591934387855)
	gotSum := transaction.OutputSum()
	if wantSum != gotSum {
		t.Fatalf("sum: want %d, got %d", wantSum, gotSum)
	}
	wantLen := 1
	gotLen := len(transaction.vin)
	if wantLen != gotLen {
		t.Fatalf("input len: want %d, got %d", wantLen, gotLen)
	}
	wantIn := []byte{0xff, 0x0f}
	gotIn := transaction.vin[0].TxIn()
	if bytes.Compare(wantIn, gotIn) != 0 {
		t.Fatalf("input 1: want %x, got %x", wantIn, gotIn)
	}
	wantLen = 9
	gotLen = len(transaction.vout)
	if wantLen != gotLen {
		t.Fatalf("output len: want %d, got %d", wantLen, gotLen)
	}
	wantOutHex := "02a3ef0df2a51b14891676b39f18d6c0b8c52bfc3f6ba5f63f792e993f73b900df"
	wantOut, _ := hex.DecodeString(wantOutHex)
	gotOut := transaction.vout[0].target.TxOutTarget()
	if bytes.Compare(wantOut, gotOut) != 0 {
		t.Fatalf("input 1: want %x, got %x", wantOut, gotOut)
	}
	gotSerialized := transaction.Serialize()
	if bytes.Compare(serializedTx, gotSerialized) != 0 {
		t.Fatalf("serialized: want %x, got %x", serializedTx, gotSerialized)
	}

}
