package moneroutil

type Hash [32]byte
type PubKey [32]byte
type Signature struct {
	c []byte
	r []byte
}

type txOutToScript struct {
	pubKeys []PubKey
	script  []byte
}

type txOutToScriptHash struct {
	hash Hash
}

type txOutToKey struct {
	pubkey PubKey
}

type TxOutTargeter interface {
	TxOutTarget() []byte
}

type txInGen struct {
	height uint64
}

type txInToScript struct {
	prev    []byte
	prevout uint64
	sigSet  []byte
}

type txInToScriptHash struct {
	prev          Hash
	prevout       uint64
	txOutToScript []byte
	sigSet        []byte
}

type txInToKey struct {
	amount     uint64
	keyOffsets []uint64
	keyImage   PubKey
}

type TxInMaker interface {
	TxIn() []byte
}

type TxOut struct {
	amount  uint64
	targets TxOutTargeter
}

type TransactionPrefix struct {
	version    uint32
	unlockTime uint64
	vin        []TxInMaker
	vout       TxOut
	extra      []byte
}

type Transaction struct {
	TransactionPrefix
	signatures     []Signature
	ringSignatures []RingSignature
	hash           []byte
	blobSize       uint32
}
