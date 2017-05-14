package moneroutil

import (
	"fmt"
	"io"
	"math/rand"
)

type RingSignatureElement struct {
	c *Key
	r *Key
}

type RingSignature []*RingSignatureElement

func (r *RingSignatureElement) Serialize() (result []byte) {
	result = make([]byte, 2*KeyLength)
	copy(result[:KeyLength], r.c[:])
	copy(result[KeyLength:2*KeyLength], r.r[:])
	return
}

func (r *RingSignature) Serialize() (result []byte) {
	result = make([]byte, len(*r)*KeyLength*2)
	for i := 0; i < len(*r); i++ {
		copy(result[i*KeyLength*2:(i+1)*KeyLength*2], (*r)[i].Serialize())
	}
	return
}

func NewRingSignatureElement() (r *RingSignatureElement) {
	r = &RingSignatureElement{
		c: new(Key),
		r: new(Key),
	}
	return
}

func ParseSignature(buf io.Reader) (result *RingSignatureElement, err error) {
	rse := NewRingSignatureElement()
	c := make([]byte, KeyLength)
	n, err := buf.Read(c)
	if err != nil {
		return
	}
	if n != KeyLength {
		err = fmt.Errorf("Not enough bytes for signature c")
		return
	}
	copy(rse.c[:], c)
	r := make([]byte, KeyLength)
	n, err = buf.Read(r)
	if err != nil {
		return
	}
	if n != KeyLength {
		err = fmt.Errorf("Not enough bytes for signature r")
		return
	}
	copy(rse.r[:], r)
	result = rse
	return
}

func ParseSignatures(mixinLengths []int, buf io.Reader) (signatures []RingSignature, err error) {
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

func HashToScalar(data ...[]byte) (result *Key) {
	result = new(Key)
	*result = Key(Keccak256(data...))
	ScReduce32(result)
	return
}

func CreateSignature(prefixHash *Hash, mixins []Key, privKey *Key) (keyImage Key, pubKeys []Key, sig RingSignature) {
	point := privKey.PubKey().HashToEC()
	keyImagePoint := new(ProjectiveGroupElement)
	GeScalarMult(keyImagePoint, privKey, point)
	// convert key Image point from Projective to Extended
	// in order to precompute
	keyImagePoint.ToBytes(&keyImage)
	keyImageGe := new(ExtendedGroupElement)
	keyImageGe.FromBytes(&keyImage)
	var keyImagePre [8]CachedGroupElement
	GePrecompute(&keyImagePre, keyImageGe)
	k := RandomScalar()
	pubKeys = make([]Key, len(mixins)+1)
	privIndex := rand.Intn(len(pubKeys))
	pubKeys[privIndex] = *privKey.PubKey()
	r := make([]*RingSignatureElement, len(pubKeys))
	sum := new(Key)
	toHash := prefixHash[:]
	for i := 0; i < len(pubKeys); i++ {
		tmpE := new(ExtendedGroupElement)
		tmpP := new(ProjectiveGroupElement)
		var tmpEBytes, tmpPBytes Key
		if i == privIndex {
			GeScalarMultBase(tmpE, k)
			tmpE.ToBytes(&tmpEBytes)
			toHash = append(toHash, tmpEBytes[:]...)
			tmpE = privKey.PubKey().HashToEC()
			GeScalarMult(tmpP, k, tmpE)
			tmpP.ToBytes(&tmpPBytes)
			toHash = append(toHash, tmpPBytes[:]...)
		} else {
			if i > privIndex {
				pubKeys[i] = mixins[i-1]
			} else {
				pubKeys[i] = mixins[i]
			}
			r[i] = &RingSignatureElement{
				c: RandomScalar(),
				r: RandomScalar(),
			}
			tmpE.FromBytes(&pubKeys[i])
			GeDoubleScalarMultVartime(tmpP, r[i].c, tmpE, r[i].r)
			tmpP.ToBytes(&tmpPBytes)
			toHash = append(toHash, tmpPBytes[:]...)
			tmpE = pubKeys[i].HashToEC()
			GeDoubleScalarMultPrecompVartime(tmpP, r[i].r, tmpE, r[i].c, &keyImagePre)
			tmpP.ToBytes(&tmpPBytes)
			toHash = append(toHash, tmpPBytes[:]...)
			ScAdd(sum, sum, r[i].c)
		}
	}
	h := HashToScalar(toHash)
	r[privIndex] = NewRingSignatureElement()
	ScSub(r[privIndex].c, h, sum)
	ScMulSub(r[privIndex].r, r[privIndex].c, privKey, k)
	sig = r
	return
}

func VerifySignature(prefixHash *Hash, keyImage *Key, pubKeys []Key, ringSignature RingSignature) (result bool) {
	keyImageGe := new(ExtendedGroupElement)
	if !keyImageGe.FromBytes(keyImage) {
		result = false
		return
	}
	var keyImagePre [8]CachedGroupElement
	GePrecompute(&keyImagePre, keyImageGe)
	toHash := prefixHash[:]
	tmpS, sum := new(Key), new(Key)
	for i, pubKey := range pubKeys {
		rse := ringSignature[i]
		if !ScValid(rse.c) || !ScValid(rse.r) {
			result = false
			return
		}
		tmpE := new(ExtendedGroupElement)
		tmpP := new(ProjectiveGroupElement)
		if !tmpE.FromBytes(&pubKey) {
			result = false
			return
		}
		var tmpPBytes, tmpEBytes Key
		GeDoubleScalarMultVartime(tmpP, rse.c, tmpE, rse.r)
		tmpP.ToBytes(&tmpPBytes)
		toHash = append(toHash, tmpPBytes[:]...)
		tmpE = pubKey.HashToEC()
		tmpE.ToBytes(&tmpEBytes)
		GeDoubleScalarMultPrecompVartime(tmpP, rse.r, tmpE, rse.c, &keyImagePre)
		tmpP.ToBytes(&tmpPBytes)
		toHash = append(toHash, tmpPBytes[:]...)
		ScAdd(sum, sum, rse.c)
	}
	tmpS = HashToScalar(toHash)
	ScSub(sum, tmpS, sum)
	result = ScIsZero(sum)
	return
}
