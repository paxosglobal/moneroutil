package moneroutil

type Key [32]byte

type ctKey struct {
	destination Key
	mask        Key
}

type ecdhTuple struct {
	mask     Key
	amount   Key
	senderPk Key
}

type RingSignatureBase struct {
	ringSigType uint8
	message     Key
	mixRing     [][]ctKey
	pseudoOuts  []Key
	ecdhInfo    []ecdhTuple
	outPk       []ctKey
	fee         uint64
}

type Key64 [64]Key

type boroSig struct {
	s0 Key64
	s1 Key64
	ee Key
}

type mgSig struct {
	ss [][]Key
	cc Key
	ii []Key
}

type rangeSig struct {
	asig boroSig
	ci   Key64
}

type RctSigPrunable struct {
	rangeSigs []rangeSig
	MGs       []mgSig
}

type RingSignature struct {
	RingSignatureBase
	RctSigPrunable
}
