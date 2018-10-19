package moneroutil

import (
	"fmt"
	"io"
)

const (
	RCTTypeNull = iota
	RCTTypeFull
	RCTTypeSimple
)

// Pedersen Commitment is generated from this struct
// C = aG + bH where a = mask and b = amount
// senderPk is the one-time public key for ECDH exchange
type ecdhTuple struct {
	mask     Key
	amount   Key
	senderPk Key
}

// Range proof commitments
type Key64 [64]Key

// Borromean Signature
type BoroSig struct {
	s0 Key64
	s1 Key64
	ee Key
}

// MLSAG (Multilayered Linkable Spontaneous Anonymous Group) Signature
type MlsagSig struct {
	ss [][]Key
	cc Key
	ii []Key
}

// Range Signature
// Essentially data for a Borromean Signature
type RangeSig struct {
	asig BoroSig
	ci   Key64
}

// Confidential Transaction Keys
type CtKey struct {
	destination Key
	mask        Key
}

// Ring Confidential Signature parts that we have to keep
type RctSigBase struct {
	sigType    uint8
	message    Key
	mixRing    [][]CtKey
	pseudoOuts []Key
	ecdhInfo   []ecdhTuple
	outPk      []CtKey
	txFee      uint64
}

// Ring Confidential Signature parts that we can just prune later
type RctSigPrunable struct {
	rangeSigs []RangeSig
	mlsagSigs []MlsagSig
}

// Ring Confidential Signature struct that can verify everything
type RctSig struct {
	RctSigBase
	RctSigPrunable
}

func (k *Key) ToExtended() (result *ExtendedGroupElement) {
	result = new(ExtendedGroupElement)
	result.FromBytes(k)
	return
}

func identity() (result *Key) {
	result = new(Key)
	result[0] = 1
	return
}

// convert a uint64 to a scalar
func d2h(val uint64) (result *Key) {
	result = new(Key)
	for i := 0; val > 0; i++ {
		result[i] = byte(val & 0xFF)
		val /= 256
	}
	return
}

// multiply a scalar by H (second curve point of Pedersen Commitment)
func ScalarMultH(scalar *Key) (result *Key) {
	h := new(ExtendedGroupElement)
	h.FromBytes(&H)
	resultPoint := new(ProjectiveGroupElement)
	GeScalarMult(resultPoint, scalar, h)
	result = new(Key)
	resultPoint.ToBytes(result)
	return
}

// add two points together
func AddKeys(sum, k1, k2 *Key) {
	a := k1.ToExtended()
	b := new(CachedGroupElement)
	k2.ToExtended().ToCached(b)
	c := new(CompletedGroupElement)
	geAdd(c, a, b)
	tmp := new(ExtendedGroupElement)
	c.ToExtended(tmp)
	tmp.ToBytes(sum)
	return
}

// compute a*G + b*B
func AddKeys2(result, a, b, B *Key) {
	BPoint := B.ToExtended()
	RPoint := new(ProjectiveGroupElement)
	GeDoubleScalarMultVartime(RPoint, b, BPoint, a)
	RPoint.ToBytes(result)
	return
}

// subtract two points A - B
func SubKeys(diff, k1, k2 *Key) {
	a := k1.ToExtended()
	b := new(CachedGroupElement)
	k2.ToExtended().ToCached(b)
	c := new(CompletedGroupElement)
	geSub(c, a, b)
	tmp := new(ExtendedGroupElement)
	c.ToExtended(tmp)
	tmp.ToBytes(diff)
	return
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

func (m *MlsagSig) Serialize() (result []byte) {
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
	for _, mlsagSig := range r.mlsagSigs {
		result = append(result, mlsagSig.Serialize()...)
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

func verBorromean(b *BoroSig, p1, p2 *Key64) bool {
	var data []byte
	tmp, tmp2 := new(Key), new(Key)
	for i := 0; i < 64; i++ {
		AddKeys2(tmp, &b.s0[i], &b.ee, &p1[i])
		tmp3 := HashToScalar(tmp[:])
		AddKeys2(tmp2, &b.s1[i], tmp3, &p2[i])
		data = append(data, tmp2[:]...)
	}
	computed := HashToScalar(data)
	return *computed == b.ee
}

func verRange(c *Key, as RangeSig) bool {
	var CiH Key64
	tmp := identity()
	for i := 0; i < 64; i++ {
		SubKeys(&CiH[i], &as.ci[i], &H2[i])
		AddKeys(tmp, tmp, &as.ci[i])
	}
	if *c != *tmp {
		return false
	}
	return verBorromean(&as.asig, &as.ci, &CiH)
}

// Verify a RCTTypeSimple RingCT Signature
func (r *RctSig) VerifyRctSimple() bool {
	sumOutPks := identity()
	for _, ctKey := range r.outPk {
		AddKeys(sumOutPks, sumOutPks, &ctKey.mask)
	}
	txFeeKey := ScalarMultH(d2h(r.txFee))
	AddKeys(sumOutPks, sumOutPks, txFeeKey)
	sumPseudoOuts := identity()
	for _, pseudoOut := range r.pseudoOuts {
		AddKeys(sumPseudoOuts, sumPseudoOuts, &pseudoOut)
	}
	if *sumPseudoOuts != *sumOutPks {
		return false
	}
	for i, ctKey := range r.outPk {
		if !verRange(&ctKey.mask, r.rangeSigs[i]) {
			return false
		}
	}
	return true
}

func (r *RctSig) VerifyRctFull() bool {
	for i, ctKey := range r.outPk {
		if !verRange(&ctKey.mask, r.rangeSigs[i]) {
			return false
		}
	}
	return true
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
	if r.sigType != RCTTypeFull && r.sigType != RCTTypeSimple {
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
	r.mlsagSigs = make([]MlsagSig, nMg)
	for i := 0; i < nMg; i++ {
		r.mlsagSigs[i].ss = make([][]Key, nMixin+1)
		for j := 0; j < nMixin+1; j++ {
			r.mlsagSigs[i].ss[j] = make([]Key, nSS)
			for k := 0; k < nSS; k++ {
				if r.mlsagSigs[i].ss[j][k], err = ParseKey(buf); err != nil {
					return
				}
			}
		}
		if r.mlsagSigs[i].cc, err = ParseKey(buf); err != nil {
			return
		}
	}
	result = r
	return
}
