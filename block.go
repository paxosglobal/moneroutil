package moneroutil

type BlockHeader struct {
	majorVersion uint8
	minorVersion uint8
	timeStamp    uint64
	previousHash Hash
	nonce        uint32
}

type Block struct {
	BlockHeader
	MinerTx  Transaction
	TxHashes []Hash
}
