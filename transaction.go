package moneroutil

import (
	"fmt"
	"io"
)

const (
	txInGenMarker           = 0xff
	txInToScriptMarker      = 0
	txInToScriptHashMarker  = 1
	txInToKeyMarker         = 2
	txOutToScriptMarker     = 0
	txOutToScriptHashMarker = 1
	txOutToKeyMarker        = 2
)

var UnimplementedError = fmt.Errorf("Unimplemented")

type txOutToScript struct {
	pubKeys []PubKey
	script  []byte
}

type txOutToScriptHash struct {
	hash Hash
}

type txOutToKey struct {
	key PubKey
}

type TxOutTargetSerializer interface {
	TargetSerialize() []byte
	String() string
}

type txInGen struct {
	height uint64
}

type txInToScript struct {
	prev    []byte
	prevOut uint64
	sigSet  []byte
}

type txInToScriptHash struct {
	prev    Hash
	prevOut uint64
	script  []byte
	sigSet  []byte
}

type txInToKey struct {
	amount     uint64
	keyOffsets []uint64
	keyImage   PubKey
}

type TxInSerializer interface {
	TxInSerialize() []byte
	MixinLen() int
}

type TxOut struct {
	amount uint64
	target TxOutTargetSerializer
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
}

func (h *Hash) Serialize() (result []byte) {
	result = h[:]
	return
}

func (p *PubKey) Serialize() (result []byte) {
	result = p[:]
	return
}

func (t *txOutToScript) TargetSerialize() (result []byte) {
	result = []byte{txOutToScriptMarker}
	for i, pubkey := range t.pubKeys {
		if i != 0 {
			result = append(result, byte(txOutToScriptMarker))
		}
		result = append(result, pubkey.Serialize()...)
	}
	result = append(result, t.script...)
	return
}

func (t *txOutToScript) String() (result string) {
	result = fmt.Sprintf("script: %x", t.script)
	return
}

func (t *txOutToScriptHash) TargetSerialize() (result []byte) {
	result = append([]byte{txOutToScriptHashMarker}, t.hash.Serialize()...)
	return
}

func (t *txOutToScriptHash) String() (result string) {
	result = fmt.Sprintf("hash: %x", t.hash)
	return
}

func (t *txOutToKey) TargetSerialize() (result []byte) {
	result = append([]byte{txOutToKeyMarker}, t.key.Serialize()...)
	return
}

func (t *txOutToKey) String() (result string) {
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

func (t *txInToScript) TxInSerialize() (result []byte) {
	result = append([]byte{txInToScriptMarker}, t.prev...)
	result = append(result, Uint64ToBytes(t.prevOut)...)
	result = append(result, t.sigSet...)
	return
}

func (t *txInToScript) MixinLen() int {
	return 0
}

func (t *txInToScriptHash) TxInSerialize() (result []byte) {
	result = append([]byte{txInToScriptHashMarker}, t.prev.Serialize()...)
	result = append(result, Uint64ToBytes(t.prevOut)...)
	result = append(result, t.script...)
	result = append(result, t.sigSet...)
	return
}

func (t *txInToScriptHash) MixinLen() int {
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

func (t *TxOut) Serialize() (result []byte) {
	result = append(Uint64ToBytes(t.amount), t.target.TargetSerialize()...)
	return
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

func (t *Transaction) GetHash() (result Hash) {
	if t.version == 1 {
		result = Keccak256(t.Serialize())
	} else {
		// version 2 requires first computing 3 separate hashes
		// prefix, rctBase and rctPrunable
		// and then hashing the hashes together to get the final hash
		prefixHash := Keccak256(t.SerializePrefix())
		rctBaseHash := Keccak256(t.rctSignature.SerializeBase())
		rctPrunableHash := Keccak256(t.rctSignature.SerializePrunable())
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

func ParseTxInToScript(buf io.Reader) (txIn *txInToScript, err error) {
	err = UnimplementedError
	return
}

func ParseTxInToScriptHash(buf io.Reader) (txIn *txInToScriptHash, err error) {
	err = UnimplementedError
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
	pubKey := make([]byte, PointLength)
	n, err := buf.Read(pubKey)
	if err != nil {
		return
	}
	if n != PointLength {
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
	case marker[0] == txInToScriptMarker:
		txIn, err = ParseTxInToScript(buf)
	case marker[0] == txInToScriptHashMarker:
		txIn, err = ParseTxInToScriptHash(buf)
	case marker[0] == txInToKeyMarker:
		txIn, err = ParseTxInToKey(buf)
	}
	return
}

func ParseTxOutToScript(buf io.Reader) (txOutTarget *txOutToScript, err error) {
	err = UnimplementedError
	return
}

func ParseTxOutToScriptHash(buf io.Reader) (txOutTarget *txOutToScriptHash, err error) {
	err = UnimplementedError
	return
}

func ParseTxOutToKey(buf io.Reader) (txOutTarget *txOutToKey, err error) {
	t := new(txOutToKey)
	pubKey := make([]byte, PointLength)
	n, err := buf.Read(pubKey)
	if err != nil {
		return
	}
	if n != PointLength {
		err = fmt.Errorf("Buffer not long enough for public key")
		return
	}
	copy(t.key[:], pubKey)
	txOutTarget = t
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
	case marker[0] == txOutToScriptMarker:
		t.target, err = ParseTxOutToScript(buf)
	case marker[0] == txOutToScriptHashMarker:
		t.target, err = ParseTxOutToScriptHash(buf)
	case marker[0] == txOutToKeyMarker:
		t.target, err = ParseTxOutToKey(buf)
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
	if version == 1 {
		t.signatures, err = ParseSignatures(mixinLengths, buf)
		if err != nil {
			return
		}
	} else {
		t.rctSignature, err = ParseRingCtSignature(buf, int(numInputs), int(numOutputs), mixinLengths[0]-1)
		if err != nil {
			return
		}
	}
	transaction = t
	return
}
