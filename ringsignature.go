package moneroutil

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/paxos-bankchain/ed25519/edwards25519"
)

const (
	PointLength  = 32
	ScalarLength = 32
)

type PubKey [PointLength]byte
type PrivKey [ScalarLength]byte

type RingSignatureElement struct {
	c [ScalarLength]byte
	r [ScalarLength]byte
}

type RingSignature []*RingSignatureElement

func RandomScalar() (result [ScalarLength]byte) {
	var reduceFrom [ScalarLength * 2]byte
	tmp := make([]byte, ScalarLength*2)
	rand.Read(tmp)
	copy(reduceFrom[:], tmp)
	edwards25519.ScReduce(&result, &reduceFrom)
	return
}

func (s *RingSignatureElement) Serialize() (result []byte) {
	result = make([]byte, 2*ScalarLength)
	copy(result, s.c[:])
	copy(result[ScalarLength:2*ScalarLength], s.r[:])
	return
}

func (r *RingSignature) Serialize() (result []byte) {
	for i := 0; i < len(*r); i++ {
		result = append(result, (*r)[i].Serialize()...)
	}
	return
}

func ParseSignature(buf *bytes.Buffer) (result *RingSignatureElement, err error) {
	s := new(RingSignatureElement)
	c := buf.Next(ScalarLength)
	if len(c) != ScalarLength {
		err = fmt.Errorf("Not enough bytes for signature c")
		return
	}
	copy(s.c[:], c)
	r := buf.Next(ScalarLength)
	if len(r) != ScalarLength {
		err = fmt.Errorf("Not enough bytes for signature r")
		return
	}
	copy(s.r[:], r)
	result = s
	return
}

func ParseSignatures(mixinLengths []int, buf *bytes.Buffer) (signatures []RingSignature, err error) {
	// mixinLengths is the number of mixins at each input position
	sigs := make([]RingSignature, len(mixinLengths), len(mixinLengths))
	for i, nMixin := range mixinLengths {
		sigs[i] = make([]*RingSignatureElement, nMixin, nMixin)
		for j := 0; j < nMixin; j++ {
			sigs[i][j], err = ParseSignature(buf)
			if err != nil {
				return
			}
		}
	}
	signatures = sigs
	return
}

// hashes a pubkey into an Edwards Curve element
func HashToEC(pk *PubKey, r *edwards25519.ExtendedGroupElement) {
	var p1 edwards25519.ProjectiveGroupElement
	var p2 edwards25519.CompletedGroupElement
	h := [PointLength]byte(Keccak256(pk[:]))
	p1.FromBytes(&h)
	edwards25519.GeMul8(&p2, &p1)
	p2.ToExtended(r)
}

func HashToScalar(data ...[]byte) (result [ScalarLength]byte) {
	result = Keccak256(data...)
	edwards25519.ScReduce32(&result)
	return
}

func CreateSignature(prefixHash *Hash, keyImage *PubKey, pubKeys []PubKey, privateKey PrivKey, privIndex int) (result RingSignature) {
	keyImageGe := new(edwards25519.ExtendedGroupElement)
	keyImageBytes := [PointLength]byte(*keyImage)
	keyImageGe.FromBytes(&keyImageBytes)
	var keyImagePre [8]edwards25519.CachedGroupElement
	edwards25519.GePrecompute(&keyImagePre, keyImageGe)
	var sum [ScalarLength]byte
	k := RandomScalar()
	toHash := prefixHash[:]
	r := make([]*RingSignatureElement, len(pubKeys))
	for i, pubKey := range pubKeys {
		tmpE := new(edwards25519.ExtendedGroupElement)
		tmpP := new(edwards25519.ProjectiveGroupElement)
		var tmpEBytes, tmpPBytes [PointLength]byte
		if i == privIndex {
			edwards25519.GeScalarMultBase(tmpE, &k)
			tmpE.ToBytes(&tmpEBytes)
			toHash = append(toHash, tmpEBytes[:]...)
			HashToEC(&pubKey, tmpE)
			edwards25519.GeScalarMult(tmpP, &k, tmpE)
			tmpP.ToBytes(&tmpPBytes)
			toHash = append(toHash, tmpPBytes[:]...)
		} else {
			r[i] = &RingSignatureElement{
				c: RandomScalar(),
				r: RandomScalar(),
			}
			pubKeyBytes := [PointLength]byte(pubKey)
			tmpE.FromBytes(&pubKeyBytes)
			edwards25519.GeDoubleScalarMultVartime(tmpP, &r[i].c, tmpE, &r[i].r)
			tmpP.ToBytes(&tmpPBytes)
			toHash = append(toHash, tmpPBytes[:]...)
			HashToEC(&pubKey, tmpE)
			edwards25519.GeDoubleScalarMultPrecompVartime(tmpP, &r[i].r, tmpE, &r[i].c, &keyImagePre)
			tmpP.ToBytes(&tmpPBytes)
			toHash = append(toHash, tmpPBytes[:]...)
			edwards25519.ScAdd(&sum, &sum, &r[i].c)
		}
	}
	h := HashToScalar(toHash)
	r[privIndex] = new(RingSignatureElement)
	edwards25519.ScSub(&r[privIndex].c, &h, &sum)
	scalar := [32]byte(privateKey)
	edwards25519.ScMulSub(&r[privIndex].r, &r[privIndex].c, &scalar, &k)
	result = r
	return
}

func VerifySignature(prefixHash *Hash, keyImage *PubKey, pubKeys []PubKey, ringSignature RingSignature) (result bool) {
	keyImageGe := new(edwards25519.ExtendedGroupElement)
	keyImageBytes := [PointLength]byte(*keyImage)
	if !keyImageGe.FromBytes(&keyImageBytes) {
		result = false
		return
	}
	var keyImagePre [8]edwards25519.CachedGroupElement
	edwards25519.GePrecompute(&keyImagePre, keyImageGe)
	toHash := prefixHash[:]
	var tmpS, sum [ScalarLength]byte
	for i, pubKey := range pubKeys {
		rse := ringSignature[i]
		if !edwards25519.ScValid(&rse.c) || !edwards25519.ScValid(&rse.r) {
			result = false
			return
		}
		tmpE := new(edwards25519.ExtendedGroupElement)
		tmpP := new(edwards25519.ProjectiveGroupElement)
		pubKeyBytes := [PointLength]byte(pubKey)
		if !tmpE.FromBytes(&pubKeyBytes) {
			result = false
			return
		}
		var tmpPBytes, tmpEBytes [PointLength]byte
		edwards25519.GeDoubleScalarMultVartime(tmpP, &rse.c, tmpE, &rse.r)
		tmpP.ToBytes(&tmpPBytes)
		toHash = append(toHash, tmpPBytes[:]...)
		HashToEC(&pubKey, tmpE)
		tmpE.ToBytes(&tmpEBytes)
		edwards25519.GeDoubleScalarMultPrecompVartime(tmpP, &rse.r, tmpE, &rse.c, &keyImagePre)
		tmpP.ToBytes(&tmpPBytes)
		toHash = append(toHash, tmpPBytes[:]...)
		edwards25519.ScAdd(&sum, &sum, &rse.c)
	}
	tmpS = HashToScalar(toHash)
	edwards25519.ScSub(&sum, &tmpS, &sum)
	result = edwards25519.ScIsZero(&sum)
	return
}

/* Below are structs for the CT version */

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

type RingSignatureCT struct {
	RingSignatureBase
	RctSigPrunable
}
