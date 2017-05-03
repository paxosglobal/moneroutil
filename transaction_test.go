package moneroutil

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCoinbaseTransaction(t *testing.T) {

	tests := []struct {
		name      string
		txHex     string
		hashHex   string
		version   uint32
		outputSum uint64
		inputHex  string
		blockNum  uint64
		outputs   []string
	}{
		{
			name:      "block 15",
			txHex:     "014b01ff0f098fd61702a3ef0df2a51b14891676b39f18d6c0b8c52bfc3f6ba5f63f792e993f73b900df8092f40102204e4d5992876b76cc8a30760c8fd82dbaf948cb2d858278a08f4d8db326682a8087a70e027a2328c2d86a1f84335010d183d0eef067195da4a57169ac9d1c8c1f84ec74a580d293ad03023c6411e620104487402583db89dd15245448092f339a30a4982e076c7ba0a7578094ebdc0302861696af6e92cea973fa217f3b4df3e8c43a2a1cb888b515e23d2d5d3d41ba688088aca3cf0202d3087348abe2dffa189c79f82e032f14cbd12cfd6ece0a5192ec235a4cf2c96e8090cad2c60e02feb619b90856473e906295252cc9a87abbb7f5db409579d3169be5ee23b35ab680e08d84ddcb010275cd0dbe02a00558669ef424c2d5f8cbefc8c4af711f1afde0404628c401b13580c0caf384a30202b1bb2e13bf7c1d88885b7ebf2be56e5064af24d69f3c92d9264550122eed1a0b2101bbac13803d9b7941444cc817292b91a9634fa6cee88ced917571df2e0c87ad79",
			hashHex:   "e3a799da24d9f41aac231ba2efb853ae649283feaf5e1ba46b5fc2c194414c5d",
			version:   1,
			outputSum: 17591934387855,
			blockNum:  15,
			outputs: []string{
				"02a3ef0df2a51b14891676b39f18d6c0b8c52bfc3f6ba5f63f792e993f73b900df",
				"02204e4d5992876b76cc8a30760c8fd82dbaf948cb2d858278a08f4d8db326682a",
				"027a2328c2d86a1f84335010d183d0eef067195da4a57169ac9d1c8c1f84ec74a5",
				"023c6411e620104487402583db89dd15245448092f339a30a4982e076c7ba0a757",
				"02861696af6e92cea973fa217f3b4df3e8c43a2a1cb888b515e23d2d5d3d41ba68",
				"02d3087348abe2dffa189c79f82e032f14cbd12cfd6ece0a5192ec235a4cf2c96e",
				"02feb619b90856473e906295252cc9a87abbb7f5db409579d3169be5ee23b35ab6",
				"0275cd0dbe02a00558669ef424c2d5f8cbefc8c4af711f1afde0404628c401b135",
				"02b1bb2e13bf7c1d88885b7ebf2be56e5064af24d69f3c92d9264550122eed1a0b",
			},
		},
		{
			name:      "block 1000",
			txHex:     "01a40801ffe80709d9f53102b68a80f92240fca8c0456db6aeb065c264f5b9c319ae478171e115fd04a0297c809bee0202c4abb05169a7188f37e4fcbca954cda85887ecd651ea986ca66748cf2cfed60480ade20402bdda1625687fad38c89473db3a0eb77294ca39e71f4771dcdf4e13bd124ff62d8088debe010276910ddc3da7c84b2d6ac9edc640d70025dd10e972d646670d453b6b9576bfca80e497d0120264ec845e5e738fa650d4d109c8c8972cbe657edc8494d0040d40abec1f2c0d7a80f8cce284020267c9d11fccc47abd45fe2b9cab90ee625ce7c0f63d19193a57fcb6971e9241628090cad2c60e02d66329f76861f0390a21d3133194aa2ac674b657743036fad3dcce1e1e87e82a80e08d84ddcb010205de735f3a734a84032b418f48d2520c7e1a7111767b937a1fe18cd4739b088880c0caf384a30202efb9148c55da56343bb95f4cf1f4b81965979e15f5365fc1d5701be197d6fa942101df90bfecd9e549ad895b79f9313a8cc43139c0b30c0258b0f41173e729ca9457",
			hashHex:   "80be5324c155542182a73bf29480d4c1d5cf71eb4931c1934b55699e56c2bbb2",
			version:   1,
			outputSum: 17575416817881,
			blockNum:  1000,
			outputs: []string{
				"02b68a80f92240fca8c0456db6aeb065c264f5b9c319ae478171e115fd04a0297c",
				"02c4abb05169a7188f37e4fcbca954cda85887ecd651ea986ca66748cf2cfed604",
				"02bdda1625687fad38c89473db3a0eb77294ca39e71f4771dcdf4e13bd124ff62d",
				"0276910ddc3da7c84b2d6ac9edc640d70025dd10e972d646670d453b6b9576bfca",
				"0264ec845e5e738fa650d4d109c8c8972cbe657edc8494d0040d40abec1f2c0d7a",
				"0267c9d11fccc47abd45fe2b9cab90ee625ce7c0f63d19193a57fcb6971e924162",
				"02d66329f76861f0390a21d3133194aa2ac674b657743036fad3dcce1e1e87e82a",
				"0205de735f3a734a84032b418f48d2520c7e1a7111767b937a1fe18cd4739b0888",
				"02efb9148c55da56343bb95f4cf1f4b81965979e15f5365fc1d5701be197d6fa94",
			},
		},
		{
			name:      "block 8888",
			txHex:     "01f44501ffb84509febd1c0248b0d7b09734048effc6b1569d7b05151758be513e5453ef88fd95820343b57280897a02b22e6274bdd728d08b24c007cc4a9e91bcdfd310f1c9cc3875d31c9c8206b0fa808ece1c02bfb5c533d2ac90d4d14d060fe371efa32190e96d06d1803db5cd4307ffc7b4b680cee4cd02026140a3a863a74bdc7a262580cc01baf4828d8b3937291aaeb6aabbbb6e9f57c080bcc1960b021c9b3b52b902d43a4f76ef89e752bb2c578deef154fd88ebefe10d9b24a30ac880a0be81950102fed41abd242c982d9f208d56bc1d9e22d07d682e048c2335401354da98aeb06180c0ee8ed20b023e1a313da690b4fdbb89032c97c75984ebd967e219102cc12bede3bfcf44c07b80e08d84ddcb01028a415ad5926c7c4d9792e5d107ce3af9069d785dc38366b6e2bf32ba8c5837e280c0caf384a302025233b2401a9ae95654b0bd9da298fc101b0ae49da8db765caef045b2da21367a210178598f5650a92b7bfb1fee24cbb49e989479e5aa37448eb2f0827189be58827a",
			hashHex:   "f6afe8b7c122722612c550d169fcf532cc9d7fafff29de1ae95129fdd9194a91",
			version:   1,
			outputSum: 17443762466686,
			blockNum:  8888,
			outputs: []string{
				"0248b0d7b09734048effc6b1569d7b05151758be513e5453ef88fd95820343b572",
				"02b22e6274bdd728d08b24c007cc4a9e91bcdfd310f1c9cc3875d31c9c8206b0fa",
				"02bfb5c533d2ac90d4d14d060fe371efa32190e96d06d1803db5cd4307ffc7b4b6",
				"026140a3a863a74bdc7a262580cc01baf4828d8b3937291aaeb6aabbbb6e9f57c0",
				"021c9b3b52b902d43a4f76ef89e752bb2c578deef154fd88ebefe10d9b24a30ac8",
				"02fed41abd242c982d9f208d56bc1d9e22d07d682e048c2335401354da98aeb061",
				"023e1a313da690b4fdbb89032c97c75984ebd967e219102cc12bede3bfcf44c07b",
				"028a415ad5926c7c4d9792e5d107ce3af9069d785dc38366b6e2bf32ba8c5837e2",
				"025233b2401a9ae95654b0bd9da298fc101b0ae49da8db765caef045b2da21367a",
			},
		},
		{
			name:      "block 65000",
			txHex:     "01a4fc0301ffe8fb0308adb32602daeb7d2fb79539dbd28b16295db665c31551eb96c02d7fdb638b524a2bda74428092f40102e547e5609175ba6f206dfb480d991f7d1ff6cfe001aa57440474359c1869087e80ade20402338ddf2a19c7455dc1c51e14f3bf07e16b353119f6226dafc4369d010fcc5c4d80b4c4c321021d1486e4d33e95da67bfdb75e5555b19e31d17a84217a11f7f2aa38900e4532180f8cce284020249147ecd5f4fbc64ec9b9eb17f044ac13e7c5f196dbd7206d8c0ad595dd83c0b80c0ee8ed20b0216c402a1c00c00997b6bb250747cfa809be45a7bf9a503339a768c3ec09908ce80c0f9decfae0102c396f8b1ad626c31ac39b5daceaec904dff69265b8f734563cfb946814c3173280c0caf384a30202ee1a068ee5d4bfe3414e89f9ba05b5b1d899060dc609025f03a49ef9a4d9daa350017fe72e842760bc591d4e03c82b9e4b7de49c85c92b702bb779ae3553b7f4db28020800000001169200a200000000000000000000000000000000000000000000000000000000000000000000000000",
			hashHex:   "afe70adf7d09948952e9a968137bf09b19e05b1fd880883762bcb6dc9aeac7f9",
			version:   1,
			outputSum: 16479014629165,
			blockNum:  65000,
			outputs: []string{
				"02daeb7d2fb79539dbd28b16295db665c31551eb96c02d7fdb638b524a2bda7442",
				"02e547e5609175ba6f206dfb480d991f7d1ff6cfe001aa57440474359c1869087e",
				"02338ddf2a19c7455dc1c51e14f3bf07e16b353119f6226dafc4369d010fcc5c4d",
				"021d1486e4d33e95da67bfdb75e5555b19e31d17a84217a11f7f2aa38900e45321",
				"0249147ecd5f4fbc64ec9b9eb17f044ac13e7c5f196dbd7206d8c0ad595dd83c0b",
				"0216c402a1c00c00997b6bb250747cfa809be45a7bf9a503339a768c3ec09908ce",
				"02c396f8b1ad626c31ac39b5daceaec904dff69265b8f734563cfb946814c31732",
				"02ee1a068ee5d4bfe3414e89f9ba05b5b1d899060dc609025f03a49ef9a4d9daa3",
			},
		},
	}
	for _, test := range tests {
		serializedTx, _ := hex.DecodeString(test.txHex)
		expectedHash, _ := hex.DecodeString(test.hashHex)
		hash := Keccak256(serializedTx)
		if bytes.Compare(expectedHash, hash) != 0 {
			t.Errorf("%s: want %x, got %x", test.name, expectedHash, hash)
		}
		buffer := new(bytes.Buffer)
		buffer.Write(serializedTx)
		transaction, err := ParseTransaction(buffer)
		if err != nil {
			t.Errorf("%s: error parsing tx: %s", test.name, err)
		}
		if test.version != transaction.version {
			t.Errorf("%s: version: want %d, got %d", test.name, test.version, transaction.version)
		}
		wantUnlockTime := uint64(test.blockNum + 60)
		if wantUnlockTime != transaction.unlockTime {
			t.Errorf("%s: unlock: want %d, got %d", test.name, wantUnlockTime, transaction.unlockTime)
		}
		gotSum := transaction.OutputSum()
		if test.outputSum != gotSum {
			t.Errorf("%s: sum: want %d, got %d", test.name, test.outputSum, gotSum)
		}
		gotLen := len(transaction.vin)
		if 1 != gotLen {
			t.Errorf("%s: input len: want %d, got %d", test.name, 1, gotLen)
		}
		wantIn := append([]byte{0xff}, Uint64ToBytes(test.blockNum)...)
		gotIn := transaction.vin[0].TxIn()
		if bytes.Compare(wantIn, gotIn) != 0 {
			t.Errorf("%s: input 0: want %x, got %x", test.name, wantIn, gotIn)
		}
		wantLen := len(test.outputs)
		gotLen = len(transaction.vout)
		if wantLen != gotLen {
			t.Errorf("%s: output len: want %d, got %d", test.name, wantLen, gotLen)
		}
		for i, output := range test.outputs {
			wantOut, _ := hex.DecodeString(output)
			gotOut := transaction.vout[i].target.TargetSerialize()
			if bytes.Compare(wantOut, gotOut) != 0 {
				t.Errorf("%s: output %d: want %x, got %x", test.name, i, wantOut, gotOut)
			}
		}
		gotSerialized := transaction.Serialize()
		if bytes.Compare(serializedTx, gotSerialized) != 0 {
			t.Errorf("%s: serialized: want %x, got %x", test.name, serializedTx, gotSerialized)
		}
	}
}
