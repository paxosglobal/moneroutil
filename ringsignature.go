package moneroutil

import (
	"bytes"
	"fmt"

	"github.com/paxos-bankchain/ed25519/edwards25519"
)

const (
	PubKeyLength = 32
)

type PubKey [PubKeyLength]byte
type RingSignatureElement struct {
	c [PubKeyLength]byte
	r [PubKeyLength]byte
}

type RingSignature []*RingSignatureElement

func Reverse(orig [32]byte) (result [32]byte) {
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		result[i], result[j] = orig[j], orig[i]
	}
	return
}

func (s *RingSignatureElement) Serialize() (result []byte) {
	result = make([]byte, 64)
	copy(result, s.c[:])
	copy(result[32:64], s.r[:])
	return
}

func ParseSignature(buf *bytes.Buffer) (result *RingSignatureElement, err error) {
	s := new(RingSignatureElement)
	c := buf.Next(PubKeyLength)
	if len(c) != PubKeyLength {
		err = fmt.Errorf("Not enough bytes for signature c")
		return
	}
	copy(s.c[:], c)
	r := buf.Next(PubKeyLength)
	if len(r) != PubKeyLength {
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
func HashToEC(pk PubKey, r *edwards25519.ExtendedGroupElement) {
	var p1 edwards25519.ProjectiveGroupElement
	var p2 edwards25519.CompletedGroupElement
	h := [32]byte(Keccak256(pk[:]))
	p1.FromBytes(&h)
	edwards25519.GeMul8(&p2, &p1)
	p2.ToExtended(r)
}

func HashToScalar(data ...[]byte) (result [32]byte) {
	result = Keccak256(data...)
	edwards25519.ScReduce32(&result)
	return
}

func VerifySignature(prefixHash Hash, keyImage PubKey, pubKeys []PubKey, ringSignature RingSignature) (result bool) {
	keyImageGe := new(edwards25519.ExtendedGroupElement)
	keyImageBytes := [32]byte(keyImage)
	keyImageGe.FromBytes(&keyImageBytes)
	var keyImagePre [8]edwards25519.CachedGroupElement
	edwards25519.GePrecompute(&keyImagePre, keyImageGe)
	toHash := prefixHash[:]
	var one, tmpS, sum [32]byte
	one[0] = 1
	for i, pubKey := range pubKeys {
		signature := ringSignature[i]
		tmpE := new(edwards25519.ExtendedGroupElement)
		tmpP := new(edwards25519.ProjectiveGroupElement)
		pubKeyBytes := [32]byte(pubKey)
		tmpE.FromBytes(&pubKeyBytes)
		var tmpPBytes, tmpEBytes [32]byte
		edwards25519.GeDoubleScalarMultVartime(tmpP, &signature.c, tmpE, &signature.r)

		tmpP.ToBytes(&tmpPBytes)
		toHash = append(toHash, tmpPBytes[:]...)
		HashToEC(pubKey, tmpE)
		tmpE.ToBytes(&tmpEBytes)
		edwards25519.GeDoubleScalarMultPrecompVartime(tmpP, &signature.r, tmpE, &signature.c, &keyImagePre)
		tmpP.ToBytes(&tmpPBytes)
		toHash = append(toHash, tmpPBytes[:]...)
		edwards25519.ScAdd(&sum, &sum, &signature.c)
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
