package moneroutil

import (
	"fmt"
	"io"
	"math/rand"
)

type RingSignatureElement struct {
	c [ScalarLength]byte
	r [ScalarLength]byte
}

type RingSignature []*RingSignatureElement

func (r *RingSignatureElement) Serialize() (result []byte) {
	result = make([]byte, 2*ScalarLength)
	copy(result[:ScalarLength], r.c[:])
	copy(result[ScalarLength:2*ScalarLength], r.r[:])
	return
}

func (r *RingSignature) Serialize() (result []byte) {
	result = make([]byte, len(*r)*ScalarLength*2)
	for i := 0; i < len(*r); i++ {
		copy(result[i*ScalarLength*2:(i+1)*ScalarLength*2], (*r)[i].Serialize())
	}
	return
}

func ParseSignature(buf io.Reader) (result *RingSignatureElement, err error) {
	rse := new(RingSignatureElement)
	c := make([]byte, ScalarLength)
	n, err := buf.Read(c)
	if err != nil {
		return
	}
	if n != ScalarLength {
		err = fmt.Errorf("Not enough bytes for signature c")
		return
	}
	copy(rse.c[:], c)
	r := make([]byte, ScalarLength)
	n, err = buf.Read(r)
	if err != nil {
		return
	}
	if n != ScalarLength {
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

func HashToScalar(data ...[]byte) (result [ScalarLength]byte) {
	result = Keccak256(data...)
	ScReduce32(&result)
	return
}

func CreateSignature(prefixHash *Hash, mixins []PubKey, privKey *PrivKey) (keyImage PubKey, pubKeys []PubKey, sig RingSignature) {
	point := privKey.PubKey().HashToEC()
	privKeyBytes := privKey.ToBytes()
	keyImagePoint := new(ProjectiveGroupElement)
	GeScalarMult(keyImagePoint, &privKeyBytes, point)
	var keyImageBytes [PointLength]byte
	// convert key Image point from Projective to Extended
	// in order to precompute
	keyImagePoint.ToBytes(&keyImageBytes)
	keyImageGe := new(ExtendedGroupElement)
	keyImageGe.FromBytes(&keyImageBytes)
	keyImage = PubKey(keyImageBytes)
	var keyImagePre [8]CachedGroupElement
	GePrecompute(&keyImagePre, keyImageGe)
	k := RandomScalar()
	pubKeys = make([]PubKey, len(mixins)+1)
	privIndex := rand.Intn(len(pubKeys))
	pubKeys[privIndex] = *privKey.PubKey()
	r := make([]*RingSignatureElement, len(pubKeys))
	var sum [ScalarLength]byte
	toHash := prefixHash[:]
	for i := 0; i < len(pubKeys); i++ {
		tmpE := new(ExtendedGroupElement)
		tmpP := new(ProjectiveGroupElement)
		var tmpEBytes, tmpPBytes [PointLength]byte
		if i == privIndex {
			GeScalarMultBase(tmpE, &k)
			tmpE.ToBytes(&tmpEBytes)
			toHash = append(toHash, tmpEBytes[:]...)
			tmpE = privKey.PubKey().HashToEC()
			GeScalarMult(tmpP, &k, tmpE)
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
			pubKeyBytes := pubKeys[i].ToBytes()
			tmpE.FromBytes(&pubKeyBytes)
			GeDoubleScalarMultVartime(tmpP, &r[i].c, tmpE, &r[i].r)
			tmpP.ToBytes(&tmpPBytes)
			toHash = append(toHash, tmpPBytes[:]...)
			tmpE = pubKeys[i].HashToEC()
			GeDoubleScalarMultPrecompVartime(tmpP, &r[i].r, tmpE, &r[i].c, &keyImagePre)
			tmpP.ToBytes(&tmpPBytes)
			toHash = append(toHash, tmpPBytes[:]...)
			ScAdd(&sum, &sum, &r[i].c)
		}
	}
	h := HashToScalar(toHash)
	r[privIndex] = new(RingSignatureElement)
	ScSub(&r[privIndex].c, &h, &sum)
	scalar := privKey.ToBytes()
	ScMulSub(&r[privIndex].r, &r[privIndex].c, &scalar, &k)
	sig = r
	return
}

func VerifySignature(prefixHash *Hash, keyImage *PubKey, pubKeys []PubKey, ringSignature RingSignature) (result bool) {
	keyImageGe := new(ExtendedGroupElement)
	keyImageBytes := [PointLength]byte(*keyImage)
	if !keyImageGe.FromBytes(&keyImageBytes) {
		result = false
		return
	}
	var keyImagePre [8]CachedGroupElement
	GePrecompute(&keyImagePre, keyImageGe)
	toHash := prefixHash[:]
	var tmpS, sum [ScalarLength]byte
	for i, pubKey := range pubKeys {
		rse := ringSignature[i]
		if !ScValid(&rse.c) || !ScValid(&rse.r) {
			result = false
			return
		}
		tmpE := new(ExtendedGroupElement)
		tmpP := new(ProjectiveGroupElement)
		pubKeyBytes := [PointLength]byte(pubKey)
		if !tmpE.FromBytes(&pubKeyBytes) {
			result = false
			return
		}
		var tmpPBytes, tmpEBytes [PointLength]byte
		GeDoubleScalarMultVartime(tmpP, &rse.c, tmpE, &rse.r)
		tmpP.ToBytes(&tmpPBytes)
		toHash = append(toHash, tmpPBytes[:]...)
		tmpE = pubKey.HashToEC()
		tmpE.ToBytes(&tmpEBytes)
		GeDoubleScalarMultPrecompVartime(tmpP, &rse.r, tmpE, &rse.c, &keyImagePre)
		tmpP.ToBytes(&tmpPBytes)
		toHash = append(toHash, tmpPBytes[:]...)
		ScAdd(&sum, &sum, &rse.c)
	}
	tmpS = HashToScalar(toHash)
	ScSub(&sum, &tmpS, &sum)
	result = ScIsZero(&sum)
	return
}
