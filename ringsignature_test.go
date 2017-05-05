package moneroutil

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	tests := []struct {
		name                  string
		prefixHashHex         string
		keyImageHex           string
		pubKeys               []string
		ringSignatureElements []string
	}{
		{
			name:          "from monero cryptotest.pl 1",
			prefixHashHex: "8e41962058b7422e7404253121489a3e63d186ed115086919a75105661483ba9",
			keyImageHex:   "350b7ead2fc72a3c5ac7f864e6bed350d6c8ca8e56f98757c2a035e0eb67f71f",
			pubKeys: []string{
				"a403aa1c2dab5fe95e847d50a048025936aefb12b6af10a13d462bd792c93a51",
				"664422cf6f4100dc6b3298e41ca53b173a98918fc9cb50fc2d590b7d1285f4ab",
				"1eb0e3db58e142cf4add0062479aa32f643e9952938eccfb0f95a841c1539129",
			},
			ringSignatureElements: []string{
				"a6a8f9248a30dca0253627e1ca1a207c48830668777fe8173aa7f8a074349204519d759714264bd129962b263a96c6a76ec9e76f9d6080180adb7b1d2f562d06",
				"d3c9f830689ed3a611ac84fe19f8de70e50c2ddf1b1067b8495a3e046b104908b1bdb749c159cde2f808c39d62ccafc355f03207105c6a73ed3eaf66b8a29a09",
				"9093e4f426b1a1360d4ade97dbdcf8f7745e6dbe9421be5a19b76a3ca511a907bc9b4379ce4168555e40e7f36211aab9f4ced5e0ace3c6845da2cb966d45d601",
			},
		},
		{
			name:          "from monero cryptotest.pl 2",
			prefixHashHex: "8a597f11961935e32e0adeab2ce48b3df2d907c9b26619dad22f42ff65ab7593",
			keyImageHex:   "fb99a056b4a74d4365f64dd124897c03e0c2d3920abad533de6b4e1878edbb36",
			pubKeys: []string{
				"6a7a81a52ba91b9785b484d761bfb3ad9a473c147e17b7fbbc3992e8c97108d7",
				"0f3fe9c20b24a11bf4d6d1acd335c6a80543f1f0380590d7323caf1390c78e88",
			},
			ringSignatureElements: []string{
				"2c15e4de88ff38d655e2deef0e06a7ca4541a7754c37e7b20875cce791754508b7903a4a3aca7253bb98be335014bebb33683aedca0bc46e288e229ecfccbe0e",
				"026c8d9801f7330aa82426adf5bacf4546d83df0cc12321ede90df8c0d9aa8006acae497177b2eeaf658b813eaf50e1e06f3d1107694beff9b520c65ee624f05",
			},
		},
		{
			name:          "1/17 inputs form block 40646",
			prefixHashHex: "aeecb4170b276d2ac69a7abca86f82621f56d943c8d4a8900cd56192da8d442d",
			keyImageHex:   "c9679ba9ca8a6fa87a1352985e46ea3723489d3699ab1af075532f711739b9c5",
			pubKeys: []string{
				"6646f168c842275b31ca863f6eac8eed9e5dfc5714d5864efb62f6c340298a30",
			},
			ringSignatureElements: []string{
				"11b4d1bd92e85f38152848cbf100c6f8b15c9de5278e4506bb9131230807d60e658188593715e7980a9d9e188d2114f2a3b71541cfe66fb94413237edf36dc0a",
			},
		},
	}
	for _, test := range tests {
		prefixHash := Hash(HexToBytes(test.prefixHashHex))
		keyImage := PubKey(HexToBytes(test.keyImageHex))
		pubKeys := make([]PubKey, len(test.pubKeys))
		for i, pubKeyHex := range test.pubKeys {
			pubKeys[i] = PubKey(HexToBytes(pubKeyHex))
		}
		ringSignature := make([]*RingSignatureElement, len(test.ringSignatureElements))
		for i, ringSignatureElementHex := range test.ringSignatureElements {
			ringSignatureElementBytes, _ := hex.DecodeString(ringSignatureElementHex)
			buffer := new(bytes.Buffer)
			buffer.Write(ringSignatureElementBytes)
			ringSignature[i], _ = ParseSignature(buffer)
		}
		if !VerifySignature(prefixHash, keyImage, pubKeys, ringSignature) {
			t.Errorf("%s: signature not verified", test.name)
			continue
		}
	}
}
