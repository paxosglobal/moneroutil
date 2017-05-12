package moneroutil

const (
	RCTTypeNull = iota
	RCTTypeFull
	RCTTypeSimple
)

// Key for Confidential Transactions, can be private or public
type Key [32]byte

// V = Vector, M = Matrix
type KeyV []Key
type KeyM []KeyV

// Confidential Transaction Keys
type CtKey struct {
	destination Key
	mask        Key
}

// V = Vector, M = Matrix
type CtKeyV []CtKey
type CtKeyM []CtKeyV

// Pedersen Commitment is generated from this struct
// C = aG + bH where a = mask and b = amount
// senderPk is the one-time public key for ECDH exchange
type ecdhTuple struct {
	mask     Key
	amount   Key
	senderPk Key
}

type Key64 [64]Key

// Borromean Signature
type BoroSig struct {
	s0 Key64
	s1 Key64
	ee Key
}

// MLSAG (Multilayered Linkable Spontaneous Anonymous Group) Signature
type MgSig struct {
	ss KeyM
	cc Key
	ii KeyV
}

// Range Signature
// Essentially data for a Borromean Signature
type RangeSig struct {
	asig BoroSig
	ci   Key64
}

// Ring Confidential Signature
type RctSigBase struct {
	sigType    uint8
	message    Key
	mixRing    CtKeyM
	pseudoOuts KeyV
	ecdhInfo   []ecdhTuple
	outPk      CtKeyV
	txnFee     uint64
}

type RctSigPrunable struct {
	rangeSigs []RangeSig
	MGs       []MgSig
}

type RctSig struct {
	RctSigBase
	RctSigPrunable
}
