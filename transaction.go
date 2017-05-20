package moneroutil

import (
	"fmt"
	"io"
)

const (
	txInGenMarker    = 0xff
	txInToKeyMarker  = 2
	txOutToKeyMarker = 2
)

var UnimplementedError = fmt.Errorf("Unimplemented")

type txInGen struct {
	height uint64
}

type txInToKey struct {
	amount     uint64
	keyOffsets []uint64
	keyImage   Key
}

type TxInSerializer interface {
	TxInSerialize() []byte
	MixinLen() int
}

type TxOut struct {
	amount uint64
	key    Key
}

type TransactionPrefix struct {
	version    uint32
	unlockTime uint64
	vin        []TxInSerializer
	vout       []*TxOut
	extra      []byte
}

type Transaction struct {
	TransactionPrefix
	signatures   []RingSignature
	rctSignature *RctSig
	expanded     bool
}

func (h *Hash) Serialize() (result []byte) {
	result = h[:]
	return
}

func (p *Key) Serialize() (result []byte) {
	result = p[:]
	return
}

func (t *TxOut) Serialize() (result []byte) {
	result = append(Uint64ToBytes(t.amount), txOutToKeyMarker)
	result = append(result, t.key[:]...)
	return
}

func (t *TxOut) String() (result string) {
	result = fmt.Sprintf("key: %x", t.key)
	return
}

func (t *txInGen) TxInSerialize() (result []byte) {
	result = append([]byte{txInGenMarker}, Uint64ToBytes(t.height)...)
	return
}

func (t *txInGen) MixinLen() int {
	return 0
}

func (t *txInToKey) TxInSerialize() (result []byte) {
	result = append([]byte{txInToKeyMarker}, Uint64ToBytes(t.amount)...)
	result = append(result, Uint64ToBytes(uint64(len(t.keyOffsets)))...)
	for _, keyOffset := range t.keyOffsets {
		result = append(result, Uint64ToBytes(keyOffset)...)
	}
	result = append(result, t.keyImage[:]...)
	return
}

func (t *txInToKey) MixinLen() int {
	return len(t.keyOffsets)
}

func (t *TransactionPrefix) SerializePrefix() (result []byte) {
	result = append(Uint64ToBytes(uint64(t.version)), Uint64ToBytes(t.unlockTime)...)
	result = append(result, Uint64ToBytes(uint64(len(t.vin)))...)
	for _, txIn := range t.vin {
		result = append(result, txIn.TxInSerialize()...)
	}
	result = append(result, Uint64ToBytes(uint64(len(t.vout)))...)
	for _, txOut := range t.vout {
		result = append(result, txOut.Serialize()...)
	}
	result = append(result, Uint64ToBytes(uint64(len(t.extra)))...)
	result = append(result, t.extra...)
	return
}

func (t *TransactionPrefix) PrefixHash() (hash Hash) {
	hash = Keccak256(t.SerializePrefix())
	return
}

func (t *TransactionPrefix) OutputSum() (sum uint64) {
	for _, output := range t.vout {
		sum += output.amount
	}
	return
}

func (t *Transaction) Serialize() (result []byte) {
	result = t.SerializePrefix()
	if t.version == 1 {
		for i := 0; i < len(t.signatures); i++ {
			result = append(result, t.signatures[i].Serialize()...)
		}
	} else {
		result = append(result, t.rctSignature.SerializeBase()...)
		result = append(result, t.rctSignature.SerializePrunable()...)
	}
	return
}

func (t *Transaction) SerializeBase() (result []byte) {
	if t.version == 1 {
		result = t.Serialize()
	} else {
		result = append(t.SerializePrefix(), t.rctSignature.SerializeBase()...)
	}
	return
}

// ExpandTransaction does nothing for version 1 transactions, but for version 2
// derives all the implied elements of the ring signature
func (t *Transaction) ExpandTransaction(outputKeys [][]CtKey) {
	if t.version == 1 {
		return
	}
	r := t.rctSignature
	if r.sigType == RCTTypeNull {
		return
	}

	// fill in the outPk property of the ring signature
	for i, ctKey := range r.outPk {
		ctKey.destination = t.vout[i].key
	}

	r.message = Key(t.PrefixHash())
	if r.sigType == RCTTypeFull {
		r.mixRing = make([][]CtKey, len(outputKeys[0]))
		for i := 0; i < len(outputKeys); i++ {
			r.mixRing[i] = make([]CtKey, len(outputKeys))
			for j := 0; j < len(outputKeys[0]); j++ {
				r.mixRing[j][i] = outputKeys[i][j]
			}
		}
		r.mlsagSigs = make([]MlsagSig, 1)
		r.mlsagSigs[0].ii = make([]Key, len(t.vin))
		for i, txIn := range t.vin {
			txInWithKey, _ := txIn.(*txInToKey)
			r.mlsagSigs[0].ii[i] = txInWithKey.keyImage
		}
	} else if r.sigType == RCTTypeSimple {
		r.mixRing = outputKeys
		r.mlsagSigs = make([]MlsagSig, len(t.vin))
		for i, txIn := range t.vin {
			txInWithKey, _ := txIn.(*txInToKey)
			r.mlsagSigs[i].ii = make([]Key, 1)
			r.mlsagSigs[i].ii[0] = txInWithKey.keyImage
		}
	}
	t.expanded = true
}

func (t *Transaction) GetHash() (result Hash) {
	if t.version == 1 {
		result = Keccak256(t.Serialize())
	} else {
		// version 2 requires first computing 3 separate hashes
		// prefix, rctBase and rctPrunable
		// and then hashing the hashes together to get the final hash
		prefixHash := t.PrefixHash()
		rctBaseHash := t.rctSignature.BaseHash()
		rctPrunableHash := t.rctSignature.PrunableHash()
		result = Keccak256(prefixHash[:], rctBaseHash[:], rctPrunableHash[:])
	}
	return
}

func ParseTxInGen(buf io.Reader) (txIn *txInGen, err error) {
	t := new(txInGen)
	t.height, err = ReadVarInt(buf)
	if err != nil {
		return
	}
	txIn = t
	return
}

func ParseTxInToKey(buf io.Reader) (txIn *txInToKey, err error) {
	t := new(txInToKey)
	t.amount, err = ReadVarInt(buf)
	if err != nil {
		return
	}
	keyOffsetLen, err := ReadVarInt(buf)
	if err != nil {
		return
	}
	t.keyOffsets = make([]uint64, keyOffsetLen, keyOffsetLen)
	for i := 0; i < int(keyOffsetLen); i++ {
		t.keyOffsets[i], err = ReadVarInt(buf)
		if err != nil {
			return
		}
	}
	pubKey := make([]byte, KeyLength)
	n, err := buf.Read(pubKey)
	if err != nil {
		return
	}
	if n != KeyLength {
		err = fmt.Errorf("Buffer not long enough for public key")
		return
	}
	copy(t.keyImage[:], pubKey)
	txIn = t
	return
}

func ParseTxIn(buf io.Reader) (txIn TxInSerializer, err error) {
	marker := make([]byte, 1)
	n, err := buf.Read(marker)
	if n != 1 {
		err = fmt.Errorf("Buffer not enough for TxIn")
		return
	}
	if err != nil {
		return
	}
	switch {
	case marker[0] == txInGenMarker:
		txIn, err = ParseTxInGen(buf)
	case marker[0] == txInToKeyMarker:
		txIn, err = ParseTxInToKey(buf)
	}
	return
}

func ParseTxOut(buf io.Reader) (txOut *TxOut, err error) {
	t := new(TxOut)
	t.amount, err = ReadVarInt(buf)
	if err != nil {
		return
	}
	marker := make([]byte, 1)
	n, err := buf.Read(marker)
	if err != nil {
		return
	}
	if n != 1 {
		err = fmt.Errorf("Buffer not long enough for TxOut")
		return
	}
	switch {
	case marker[0] == txOutToKeyMarker:
		t.key, err = ParseKey(buf)
	default:
		err = fmt.Errorf("Bad Marker")
		return
	}
	if err != nil {
		return
	}
	txOut = t
	return
}

func ParseExtra(buf io.Reader) (extra []byte, err error) {
	length, err := ReadVarInt(buf)
	if err != nil {
		return
	}
	e := make([]byte, int(length))
	n, err := buf.Read(e)
	if err != nil {
		return
	}
	if n != int(length) {
		err = fmt.Errorf("Not enough bytes for extra")
		return
	}
	extra = e
	return
}

func ParseTransaction(buf io.Reader) (transaction *Transaction, err error) {
	t := new(Transaction)
	version, err := ReadVarInt(buf)
	if err != nil {
		return
	}
	t.version = uint32(version)
	t.unlockTime, err = ReadVarInt(buf)
	if err != nil {
		return
	}
	numInputs, err := ReadVarInt(buf)
	if err != nil {
		return
	}
	var mixinLengths []int
	t.vin = make([]TxInSerializer, int(numInputs), int(numInputs))
	for i := 0; i < int(numInputs); i++ {
		t.vin[i], err = ParseTxIn(buf)
		if err != nil {
			return
		}
		mixinLen := t.vin[i].MixinLen()
		if mixinLen > 0 {
			mixinLengths = append(mixinLengths, mixinLen)
		}
	}
	numOutputs, err := ReadVarInt(buf)
	if err != nil {
		return
	}
	t.vout = make([]*TxOut, int(numOutputs), int(numOutputs))
	for i := 0; i < int(numOutputs); i++ {
		t.vout[i], err = ParseTxOut(buf)
		if err != nil {
			return
		}
	}
	t.extra, err = ParseExtra(buf)
	if err != nil {
		return
	}
	if t.version == 1 {
		t.signatures, err = ParseSignatures(mixinLengths, buf)
		if err != nil {
			return
		}
	} else {
		var nMixins int
		if len(mixinLengths) > 0 {
			nMixins = mixinLengths[0] - 1
		}
		t.rctSignature, err = ParseRingCtSignature(buf, int(numInputs), int(numOutputs), nMixins)
		if err != nil {
			return
		}
	}
	transaction = t
	return
}
