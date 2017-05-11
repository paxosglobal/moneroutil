package moneroutil

import (
	"crypto/rand"
)

const (
	PointLength  = 32
	ScalarLength = 32
)

type PubKey [PointLength]byte
type PrivKey [ScalarLength]byte

func (p *PrivKey) FromBytes(b [ScalarLength]byte) {
	*p = b
}

func (p *PrivKey) ToBytes() (result [ScalarLength]byte) {
	result = [32]byte(*p)
	return
}

func (p *PrivKey) PubKey() (pubKey *PubKey) {
	secret := p.ToBytes()
	point := new(ExtendedGroupElement)
	GeScalarMultBase(point, &secret)
	pubKeyBytes := new([PointLength]byte)
	point.ToBytes(pubKeyBytes)
	pubKey = (*PubKey)(pubKeyBytes)
	return
}

func (p *PubKey) FromBytes(b [PointLength]byte) {
	*p = b
}

func (p *PubKey) ToBytes() (result [PointLength]byte) {
	result = [PointLength]byte(*p)
	return
}

// Creates a point on the Edwards Curve by hashing the key
func (p *PubKey) HashToEC() (result *ExtendedGroupElement) {
	result = new(ExtendedGroupElement)
	var p1 ProjectiveGroupElement
	var p2 CompletedGroupElement
	h := [PointLength]byte(Keccak256(p[:]))
	p1.FromBytes(&h)
	GeMul8(&p2, &p1)
	p2.ToExtended(result)
	return
}

func RandomScalar() (result [ScalarLength]byte) {
	var reduceFrom [ScalarLength * 2]byte
	tmp := make([]byte, ScalarLength*2)
	rand.Read(tmp)
	copy(reduceFrom[:], tmp)
	ScReduce(&result, &reduceFrom)
	return
}

func NewKeyPair() (privKey *PrivKey, pubKey *PubKey) {
	privKey = new(PrivKey)
	pubKey = new(PubKey)
	privKey.FromBytes(RandomScalar())
	pubKey = privKey.PubKey()
	return
}
