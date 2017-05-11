package moneroutil

import (
	"bytes"
	"errors"
	"fmt"
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
	signatures []RingSignature
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
	result = []byte{txInToScriptMarker}
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
	result = append([]byte{txInToScriptHashMarker}, t.hash.Serialize()...)
	return
}

func (t *txOutToScriptHash) String() (result string) {
	result = fmt.Sprintf("hash: %x", t.hash)
	return
}

func (t *txOutToKey) TargetSerialize() (result []byte) {
	result = append([]byte{txInToKeyMarker}, t.key.Serialize()...)
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
	for i := 0; i < len(t.signatures); i++ {
		result = append(result, t.signatures[i].Serialize()...)
	}
	return
}

func ParseTxInGen(buf *bytes.Buffer) (txIn *txInGen, err error) {
	t := new(txInGen)
	t.height, err = ReadVarInt(buf)
	if err != nil {
		return
	}
	txIn = t
	return
}

func ParseTxInToScript(buf *bytes.Buffer) (txIn *txInToScript, err error) {
	err = errors.New("Unimplemented")
	return
}

func ParseTxInToScriptHash(buf *bytes.Buffer) (txIn *txInToScriptHash, err error) {
	err = errors.New("Unimplemented")
	return
}

func ParseTxInToKey(buf *bytes.Buffer) (txIn *txInToKey, err error) {
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
	pubKey := buf.Next(PointLength)
	if len(pubKey) != PointLength {
		err = errors.New("Buffer not long enough for public key")
		return
	}
	copy(t.keyImage[:], pubKey)
	txIn = t
	return
}

func ParseTxIn(buf *bytes.Buffer) (txIn TxInSerializer, err error) {
	marker, err := buf.ReadByte()
	if err != nil {
		return
	}
	switch {
	case marker == txInGenMarker:
		txIn, err = ParseTxInGen(buf)
	case marker == txInToScriptMarker:
		txIn, err = ParseTxInToScript(buf)
	case marker == txInToScriptHashMarker:
		txIn, err = ParseTxInToScriptHash(buf)
	case marker == txInToKeyMarker:
		txIn, err = ParseTxInToKey(buf)
	}
	return
}

func ParseTxOutToScript(buf *bytes.Buffer) (txOutTarget *txOutToScript, err error) {
	err = errors.New("Unimplemented")
	return
}

func ParseTxOutToScriptHash(buf *bytes.Buffer) (txOutTarget *txOutToScriptHash, err error) {
	err = errors.New("Unimplemented")
	return
}

func ParseTxOutToKey(buf *bytes.Buffer) (txOutTarget *txOutToKey, err error) {
	t := new(txOutToKey)
	pubKey := buf.Next(PointLength)
	if len(pubKey) != PointLength {
		err = errors.New("Buffer not long enough for public key")
		return
	}
	copy(t.key[:], pubKey)
	txOutTarget = t
	return
}

func ParseTxOut(buf *bytes.Buffer) (txOut *TxOut, err error) {
	t := new(TxOut)
	t.amount, err = ReadVarInt(buf)
	if err != nil {
		return
	}
	marker, err := buf.ReadByte()
	if err != nil {
		return
	}
	switch {
	case marker == txOutToScriptMarker:
		t.target, err = ParseTxOutToScript(buf)
	case marker == txOutToScriptHashMarker:
		t.target, err = ParseTxOutToScriptHash(buf)
	case marker == txOutToKeyMarker:
		t.target, err = ParseTxOutToKey(buf)
	default:
		err = errors.New("Bad Marker")
		return
	}
	if err != nil {
		return
	}
	txOut = t
	return
}

func ParseExtra(buf *bytes.Buffer) (extra []byte, err error) {
	length, err := ReadVarInt(buf)
	if err != nil {
		return
	}
	e := buf.Next(int(length))
	if len(e) != int(length) {
		err = errors.New("Not enough bytes for extra")
		return
	}
	extra = e
	return
}

func ParseTransaction(buf *bytes.Buffer) (transaction *Transaction, err error) {
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
	t.signatures, err = ParseSignatures(mixinLengths, buf)
	if err != nil {
		return
	}
	if buf.Len() != 0 {
		err = errors.New("Buffer has extra data")
		return
	}
	transaction = t
	return
}
