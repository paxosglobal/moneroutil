package moneroutil

import (
	"fmt"
	"io"
)

const (
	RCTTypeNull = iota
	RCTTypeFull
	RCTTypeSimple

	KeyLength = 32
)

// Key for Confidential Transactions, can be private or public
type Key [KeyLength]byte

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
	txFee      uint64
}

type RctSigPrunable struct {
	rangeSigs []RangeSig
	mgSigs    []MgSig
}

type RctSig struct {
	RctSigBase
	RctSigPrunable
}

func (k *Key64) Serialize() (result []byte) {
	for _, key := range k {
		result = append(result, key[:]...)
	}
	return
}

func (b *BoroSig) Serialize() (result []byte) {
	result = append(b.s0.Serialize(), b.s1.Serialize()...)
	result = append(result, b.ee[:]...)
	return
}

func (r *RangeSig) Serialize() (result []byte) {
	result = append(r.asig.Serialize(), r.ci.Serialize()...)
	return
}

func (m *MgSig) Serialize() (result []byte) {
	for i := 0; i < len(m.ss); i++ {
		for j := 0; j < len(m.ss[i]); j++ {
			result = append(result, m.ss[i][j][:]...)
		}
	}
	result = append(result, m.cc[:]...)
	return
}

func (r *RctSigBase) SerializeBase() (result []byte) {
	result = []byte{r.sigType}
	// Null type returns right away
	if r.sigType == RCTTypeNull {
		return
	}
	result = append(result, Uint64ToBytes(r.txFee)...)
	if r.sigType == RCTTypeSimple {
		for _, input := range r.pseudoOuts {
			result = append(result, input[:]...)
		}
	}
	for _, ecdh := range r.ecdhInfo {
		result = append(result, ecdh.mask[:]...)
		result = append(result, ecdh.amount[:]...)
	}
	for _, ctKey := range r.outPk {
		result = append(result, ctKey.mask[:]...)
	}
	return
}

func (r *RctSigBase) BaseHash() (result Hash) {
	result = Keccak256(r.SerializeBase())
	return
}

func (r *RctSig) SerializePrunable() (result []byte) {
	if r.sigType == RCTTypeNull {
		return
	}
	for _, rangeSig := range r.rangeSigs {
		result = append(result, rangeSig.Serialize()...)
	}
	for _, mgSig := range r.mgSigs {
		result = append(result, mgSig.Serialize()...)
	}
	return
}

func (r *RctSig) PrunableHash() (result Hash) {
	if r.sigType == RCTTypeNull {
		return
	}
	result = Keccak256(r.SerializePrunable())
	return
}

func ParseKey(buf io.Reader) (result Key, err error) {
	key := make([]byte, KeyLength)
	if _, err = buf.Read(key); err != nil {
		return
	}
	copy(result[:], key)
	return
}

func ParseCtKey(buf io.Reader) (result CtKey, err error) {
	if result.mask, err = ParseKey(buf); err != nil {
		return
	}
	return
}

func ParseKey64(buf io.Reader) (result Key64, err error) {
	for i := 0; i < 64; i++ {
		if result[i], err = ParseKey(buf); err != nil {
			return
		}
	}
	return
}

func ParseBoroSig(buf io.Reader) (result BoroSig, err error) {
	if result.s0, err = ParseKey64(buf); err != nil {
		return
	}
	if result.s1, err = ParseKey64(buf); err != nil {
		return
	}
	if result.ee, err = ParseKey(buf); err != nil {
		return
	}
	return
}

func ParseRangeSig(buf io.Reader) (result RangeSig, err error) {
	if result.asig, err = ParseBoroSig(buf); err != nil {
		return
	}
	if result.ci, err = ParseKey64(buf); err != nil {
		return
	}
	return
}

func ParseRingCtSignature(buf io.Reader, nInputs, nOutputs, nMixin int) (result *RctSig, err error) {
	r := new(RctSig)
	sigType := make([]byte, 1)
	_, err = buf.Read(sigType)
	if err != nil {
		return
	}
	r.sigType = uint8(sigType[0])
	if r.sigType == RCTTypeNull {
		result = r
		return
	}
	if r.sigType != RCTTypeFull || r.sigType != RCTTypeSimple {
		err = fmt.Errorf("Bad sigType %d", r.sigType)
	}
	r.txFee, err = ReadVarInt(buf)
	if err != nil {
		return
	}
	var nMg, nSS int
	if r.sigType == RCTTypeSimple {
		nMg = nInputs
		nSS = 2
		r.pseudoOuts = make([]Key, nInputs)
		for i := 0; i < nInputs; i++ {
			if r.pseudoOuts[i], err = ParseKey(buf); err != nil {
				return
			}
		}
	} else {
		nMg = 1
		nSS = nInputs + 1
	}
	r.ecdhInfo = make([]ecdhTuple, nOutputs)
	for i := 0; i < nOutputs; i++ {
		if r.ecdhInfo[i].mask, err = ParseKey(buf); err != nil {
			return
		}
		if r.ecdhInfo[i].amount, err = ParseKey(buf); err != nil {
			return
		}
	}
	r.outPk = make([]CtKey, nOutputs)
	for i := 0; i < nOutputs; i++ {
		if r.outPk[i], err = ParseCtKey(buf); err != nil {
			return
		}
	}
	r.rangeSigs = make([]RangeSig, nOutputs)
	for i := 0; i < nOutputs; i++ {
		if r.rangeSigs[i], err = ParseRangeSig(buf); err != nil {
			return
		}
	}
	r.mgSigs = make([]MgSig, nMg)
	for i := 0; i < nMg; i++ {
		r.mgSigs[i].ss = make([]KeyV, nMixin+1)
		for j := 0; j < nMixin+1; j++ {
			r.mgSigs[i].ss[j] = make([]Key, nSS)
			for k := 0; k < nSS; k++ {
				if r.mgSigs[i].ss[j][k], err = ParseKey(buf); err != nil {
					return
				}
			}
		}
		if r.mgSigs[i].cc, err = ParseKey(buf); err != nil {
			return
		}
	}
	result = r
	return
}
