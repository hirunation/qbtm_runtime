// Package runtime provides a self-contained executor for qmbtree circuits.
// CRITICAL: This package must have ZERO imports from qi-genesis packages.
// It reimplements the minimal subset needed for circuit execution.
package runtime

import (
	"crypto/sha256"
	"math/big"
)

// Value represents a qmb value (minimal subset for runtime).
type Value interface {
	valueTag()
	Encode() []byte
}

// Int is an exact integer.
type Int struct{ V *big.Int }

func (Int) valueTag() {}

// Rat is an exact rational.
type Rat struct{ V *big.Rat }

func (Rat) valueTag() {}

// Bytes is a byte sequence.
type Bytes struct{ V []byte }

func (Bytes) valueTag() {}

// Text is a text string.
type Text struct{ V string }

func (Text) valueTag() {}

// Seq is a sequence of values.
type Seq struct{ Items []Value }

func (Seq) valueTag() {}

// Tag is a labeled value.
type Tag struct {
	Label   Value
	Payload Value
}

func (Tag) valueTag() {}

// Bool is a boolean value.
type Bool struct{ V bool }

func (Bool) valueTag() {}

// Nil is the nil value.
type Nil struct{}

func (Nil) valueTag() {}

// Constructors

// MakeInt creates an integer value.
func MakeInt(n int64) Int {
	return Int{V: big.NewInt(n)}
}

// MakeBigInt creates an integer value from big.Int.
func MakeBigInt(n *big.Int) Int {
	return Int{V: new(big.Int).Set(n)}
}

// MakeRat creates a rational value.
func MakeRat(num, denom int64) Rat {
	return Rat{V: big.NewRat(num, denom)}
}

// MakeBigRat creates a rational value from big.Rat.
func MakeBigRat(r *big.Rat) Rat {
	return Rat{V: new(big.Rat).Set(r)}
}

// MakeBytes creates a bytes value.
func MakeBytes(b []byte) Bytes {
	copied := make([]byte, len(b))
	copy(copied, b)
	return Bytes{V: copied}
}

// MakeText creates a text value.
func MakeText(s string) Text {
	return Text{V: s}
}

// MakeSeq creates a sequence value.
func MakeSeq(items ...Value) Seq {
	return Seq{Items: items}
}

// MakeTag creates a tagged value.
func MakeTag(label, payload Value) Tag {
	return Tag{Label: label, Payload: payload}
}

// MakeBool creates a boolean value.
func MakeBool(b bool) Bool {
	return Bool{V: b}
}

// MakeNil creates a nil value.
func MakeNil() Nil {
	return Nil{}
}

// Encode implementations

// Encode encodes an Int to bytes.
func (v Int) Encode() []byte {
	if v.V == nil || v.V.Sign() == 0 {
		return []byte{0x00} // Zero
	}
	if v.V.Sign() > 0 && v.V.BitLen() <= 7 {
		return []byte{byte(v.V.Int64())} // Small positive
	}
	// Larger integers
	bytes := v.V.Bytes()
	result := make([]byte, 0, len(bytes)+2)
	if v.V.Sign() < 0 {
		result = append(result, 0x80) // Negative marker
	} else {
		result = append(result, 0x40) // Positive marker
	}
	result = append(result, byte(len(bytes)))
	result = append(result, bytes...)
	return result
}

// Encode encodes a Rat to bytes.
func (v Rat) Encode() []byte {
	if v.V == nil || v.V.Sign() == 0 {
		return []byte{0x90, 0x00} // Zero rational
	}
	numBytes := v.V.Num().Bytes()
	denomBytes := v.V.Denom().Bytes()
	result := make([]byte, 0, len(numBytes)+len(denomBytes)+4)
	result = append(result, 0x90) // Rational marker

	// Sign
	if v.V.Sign() < 0 {
		result = append(result, 0x80)
	} else {
		result = append(result, 0x00)
	}

	// Numerator length and bytes
	result = append(result, byte(len(numBytes)))
	result = append(result, numBytes...)

	// Denominator length and bytes
	result = append(result, byte(len(denomBytes)))
	result = append(result, denomBytes...)

	return result
}

// Encode encodes Bytes to bytes.
func (v Bytes) Encode() []byte {
	result := make([]byte, 0, len(v.V)+5)
	result = append(result, 0xA0) // Bytes marker
	// Length as varint
	result = append(result, encodeVarint(uint64(len(v.V)))...)
	result = append(result, v.V...)
	return result
}

// Encode encodes Text to bytes.
func (v Text) Encode() []byte {
	bytes := []byte(v.V)
	result := make([]byte, 0, len(bytes)+5)
	result = append(result, 0xB0) // Text marker
	result = append(result, encodeVarint(uint64(len(bytes)))...)
	result = append(result, bytes...)
	return result
}

// Encode encodes a Seq to bytes.
func (v Seq) Encode() []byte {
	result := []byte{0xC0} // Seq marker
	result = append(result, encodeVarint(uint64(len(v.Items)))...)
	for _, item := range v.Items {
		result = append(result, item.Encode()...)
	}
	return result
}

// Encode encodes a Tag to bytes.
func (v Tag) Encode() []byte {
	result := []byte{0xD0} // Tag marker
	result = append(result, v.Label.Encode()...)
	result = append(result, v.Payload.Encode()...)
	return result
}

// Encode encodes a Bool to bytes.
func (v Bool) Encode() []byte {
	if v.V {
		return []byte{0xE1}
	}
	return []byte{0xE0}
}

// Encode encodes Nil to bytes.
func (v Nil) Encode() []byte {
	return []byte{0xF0}
}

// encodeVarint encodes a uint64 as a variable-length integer.
func encodeVarint(n uint64) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	result := make([]byte, 0, 10)
	for n >= 128 {
		result = append(result, byte(n&0x7F)|0x80)
		n >>= 7
	}
	result = append(result, byte(n))
	return result
}

// QGID computes the identity hash of a value.
func QGID(v Value) [32]byte {
	bytes := v.Encode()
	return sha256.Sum256(bytes)
}

// Equal checks if two values are equal.
func Equal(a, b Value) bool {
	switch av := a.(type) {
	case Int:
		if bv, ok := b.(Int); ok {
			return av.V.Cmp(bv.V) == 0
		}
	case Rat:
		if bv, ok := b.(Rat); ok {
			return av.V.Cmp(bv.V) == 0
		}
	case Bytes:
		if bv, ok := b.(Bytes); ok {
			if len(av.V) != len(bv.V) {
				return false
			}
			for i := range av.V {
				if av.V[i] != bv.V[i] {
					return false
				}
			}
			return true
		}
	case Text:
		if bv, ok := b.(Text); ok {
			return av.V == bv.V
		}
	case Seq:
		if bv, ok := b.(Seq); ok {
			if len(av.Items) != len(bv.Items) {
				return false
			}
			for i := range av.Items {
				if !Equal(av.Items[i], bv.Items[i]) {
					return false
				}
			}
			return true
		}
	case Tag:
		if bv, ok := b.(Tag); ok {
			return Equal(av.Label, bv.Label) && Equal(av.Payload, bv.Payload)
		}
	case Bool:
		if bv, ok := b.(Bool); ok {
			return av.V == bv.V
		}
	case Nil:
		if _, ok := b.(Nil); ok {
			return true
		}
	}
	return false
}
