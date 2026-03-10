package runtime

import (
	"fmt"
	"math/big"
)

// EmbeddedBinary represents a self-contained qmb binary.
type EmbeddedBinary struct {
	Magic      [4]byte  // "QMB\x01"
	Entrypoint [32]byte // Main circuit QGID
	Name       string   // Binary name
	Version    string   // Version string
	StoreData  []byte   // Serialized store
}

// Encode serializes the embedded binary to bytes.
func (e *EmbeddedBinary) Encode() []byte {
	nameBytes := []byte(e.Name)
	versionBytes := []byte(e.Version)

	size := 4 + 32 + 4 + len(nameBytes) + 4 + len(versionBytes) + len(e.StoreData)
	result := make([]byte, size)

	offset := 0

	// Magic
	copy(result[offset:], e.Magic[:])
	offset += 4

	// Entrypoint
	copy(result[offset:], e.Entrypoint[:])
	offset += 32

	// Name
	result[offset] = byte(len(nameBytes) >> 24)
	result[offset+1] = byte(len(nameBytes) >> 16)
	result[offset+2] = byte(len(nameBytes) >> 8)
	result[offset+3] = byte(len(nameBytes))
	offset += 4
	copy(result[offset:], nameBytes)
	offset += len(nameBytes)

	// Version
	result[offset] = byte(len(versionBytes) >> 24)
	result[offset+1] = byte(len(versionBytes) >> 16)
	result[offset+2] = byte(len(versionBytes) >> 8)
	result[offset+3] = byte(len(versionBytes))
	offset += 4
	copy(result[offset:], versionBytes)
	offset += len(versionBytes)

	// Store data
	copy(result[offset:], e.StoreData)

	return result
}

// Decode deserializes an embedded binary from bytes.
func Decode(data []byte) (*EmbeddedBinary, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short")
	}

	// Check magic
	if data[0] != 'Q' || data[1] != 'M' || data[2] != 'B' || data[3] != 0x01 {
		return nil, fmt.Errorf("invalid magic: expected QMB\\x01")
	}

	if len(data) < 36 {
		return nil, fmt.Errorf("data too short for entrypoint")
	}

	result := &EmbeddedBinary{}
	copy(result.Magic[:], data[:4])
	copy(result.Entrypoint[:], data[4:36])

	offset := 36

	// Name
	if len(data) < offset+4 {
		return nil, fmt.Errorf("data too short for name length")
	}
	nameLen := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
	offset += 4
	if len(data) < offset+nameLen {
		return nil, fmt.Errorf("data too short for name")
	}
	result.Name = string(data[offset : offset+nameLen])
	offset += nameLen

	// Version
	if len(data) < offset+4 {
		return nil, fmt.Errorf("data too short for version length")
	}
	versionLen := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
	offset += 4
	if len(data) < offset+versionLen {
		return nil, fmt.Errorf("data too short for version")
	}
	result.Version = string(data[offset : offset+versionLen])
	offset += versionLen

	// Store data
	result.StoreData = data[offset:]

	return result, nil
}

// Runner executes an embedded binary.
type Runner struct {
	binary   *EmbeddedBinary
	store    *Store
	executor *Executor
}

// NewRunner creates a runner from binary data.
func NewRunner(data []byte) (*Runner, error) {
	binary, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decode failed: %w", err)
	}

	store := NewStore()

	// Load store data
	if err := loadStoreData(store, binary.StoreData); err != nil {
		return nil, fmt.Errorf("load store failed: %w", err)
	}

	executor := NewExecutor(store)

	return &Runner{
		binary:   binary,
		store:    store,
		executor: executor,
	}, nil
}

// loadStoreData loads serialized store data.
func loadStoreData(store *Store, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	// Parse as a sequence of tagged values
	v, _, err := decodeValue(data)
	if err != nil {
		return err
	}

	// Import values
	return importValues(store, v)
}

// decodeVarint decodes a variable-length integer from data, returning the
// value and the number of bytes consumed. This is the inverse of
// encodeVarint() in value.go.
func decodeVarint(data []byte) (uint64, int, error) {
	var n uint64
	var shift uint
	for i := 0; i < len(data); i++ {
		b := data[i]
		n |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return n, i + 1, nil
		}
		shift += 7
		if shift >= 64 {
			return 0, 0, fmt.Errorf("varint overflow")
		}
	}
	return 0, 0, fmt.Errorf("varint truncated")
}

// decodeValue decodes a Value from bytes, returning the value and the number
// of bytes consumed. This is the complete inverse of the Encode() methods
// defined on each value type in value.go.
func decodeValue(data []byte) (Value, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("empty data")
	}

	tag := data[0]

	switch {
	// 0x00 → Int(0)
	case tag == 0x00:
		return MakeInt(0), 1, nil

	// 0x01-0x3F → small positive Int (value = byte itself)
	case tag >= 0x01 && tag <= 0x3F:
		return MakeInt(int64(tag)), 1, nil

	// 0x40 → positive Int (next byte = length, then big-endian bytes)
	case tag == 0x40:
		if len(data) < 2 {
			return nil, 0, fmt.Errorf("positive int: missing length byte")
		}
		byteLen := int(data[1])
		if len(data) < 2+byteLen {
			return nil, 0, fmt.Errorf("positive int: data too short, need %d bytes", byteLen)
		}
		v := new(big.Int).SetBytes(data[2 : 2+byteLen])
		return MakeBigInt(v), 2 + byteLen, nil

	// 0x80 → negative Int (next byte = length, then big-endian bytes)
	case tag == 0x80:
		if len(data) < 2 {
			return nil, 0, fmt.Errorf("negative int: missing length byte")
		}
		byteLen := int(data[1])
		if len(data) < 2+byteLen {
			return nil, 0, fmt.Errorf("negative int: data too short, need %d bytes", byteLen)
		}
		v := new(big.Int).SetBytes(data[2 : 2+byteLen])
		v.Neg(v)
		return MakeBigInt(v), 2 + byteLen, nil

	// 0x90 → Rat (sign byte, numLen, numBytes..., denomLen, denomBytes...)
	// Format is always: 0x90, sign, numLen, numBytes..., denomLen, denomBytes...
	// Zero rational: 0x90, 0x00, 0x00, 0x00 (sign=0, numLen=0, denomLen=0).
	case tag == 0x90:
		if len(data) < 2 {
			return nil, 0, fmt.Errorf("rat: missing sign byte")
		}
		signByte := data[1]
		offset := 2

		// Numerator length
		if offset >= len(data) {
			return nil, 0, fmt.Errorf("rat: missing numerator length")
		}
		numLen := int(data[offset])
		offset++
		if len(data) < offset+numLen {
			return nil, 0, fmt.Errorf("rat: data too short for numerator")
		}
		numBytes := data[offset : offset+numLen]
		offset += numLen

		// Denominator length
		if offset >= len(data) {
			return nil, 0, fmt.Errorf("rat: missing denominator length")
		}
		denomLen := int(data[offset])
		offset++
		if len(data) < offset+denomLen {
			return nil, 0, fmt.Errorf("rat: data too short for denominator")
		}
		denomBytes := data[offset : offset+denomLen]
		offset += denomLen

		// If both numerator and denominator are empty, this is zero
		if numLen == 0 && denomLen == 0 {
			return MakeRat(0, 1), offset, nil
		}

		num := new(big.Int).SetBytes(numBytes)
		denom := new(big.Int).SetBytes(denomBytes)
		if denom.Sign() == 0 {
			denom.SetInt64(1)
		}

		if signByte == 0x80 {
			num.Neg(num)
		}

		r := new(big.Rat).SetFrac(num, denom)
		return MakeBigRat(r), offset, nil

	// 0xA0 → Bytes (varint length, then raw bytes)
	case tag == 0xA0:
		length, vLen, err := decodeVarint(data[1:])
		if err != nil {
			return nil, 0, fmt.Errorf("bytes: %w", err)
		}
		offset := 1 + vLen
		if len(data) < offset+int(length) {
			return nil, 0, fmt.Errorf("bytes: data too short, need %d bytes", length)
		}
		v := make([]byte, length)
		copy(v, data[offset:offset+int(length)])
		return MakeBytes(v), offset + int(length), nil

	// 0xB0 → Text (varint length, then UTF-8 bytes)
	case tag == 0xB0:
		length, vLen, err := decodeVarint(data[1:])
		if err != nil {
			return nil, 0, fmt.Errorf("text: %w", err)
		}
		offset := 1 + vLen
		if len(data) < offset+int(length) {
			return nil, 0, fmt.Errorf("text: data too short, need %d bytes", length)
		}
		s := string(data[offset : offset+int(length)])
		return MakeText(s), offset + int(length), nil

	// 0xC0 → Seq (varint count, then each item recursively)
	case tag == 0xC0:
		count, vLen, err := decodeVarint(data[1:])
		if err != nil {
			return nil, 0, fmt.Errorf("seq: %w", err)
		}
		offset := 1 + vLen
		items := make([]Value, count)
		for i := uint64(0); i < count; i++ {
			if offset >= len(data) {
				return nil, 0, fmt.Errorf("seq: truncated at item %d", i)
			}
			item, consumed, err := decodeValue(data[offset:])
			if err != nil {
				return nil, 0, fmt.Errorf("seq item %d: %w", i, err)
			}
			items[i] = item
			offset += consumed
		}
		return MakeSeq(items...), offset, nil

	// 0xD0 → Tag (label then payload, both recursively)
	case tag == 0xD0:
		offset := 1
		if offset >= len(data) {
			return nil, 0, fmt.Errorf("tag: missing label")
		}
		label, consumed, err := decodeValue(data[offset:])
		if err != nil {
			return nil, 0, fmt.Errorf("tag label: %w", err)
		}
		offset += consumed
		if offset >= len(data) {
			return nil, 0, fmt.Errorf("tag: missing payload")
		}
		payload, consumed, err := decodeValue(data[offset:])
		if err != nil {
			return nil, 0, fmt.Errorf("tag payload: %w", err)
		}
		offset += consumed
		return MakeTag(label, payload), offset, nil

	// 0xE0 → Bool(false)
	case tag == 0xE0:
		return MakeBool(false), 1, nil

	// 0xE1 → Bool(true)
	case tag == 0xE1:
		return MakeBool(true), 1, nil

	// 0xF0 → Nil
	case tag == 0xF0:
		return MakeNil(), 1, nil

	default:
		return nil, 0, fmt.Errorf("unknown value tag: 0x%02x", tag)
	}
}

// importValues imports values into the store. The store data is expected to
// be a Seq of Tag("entry", Seq(Bytes(qgid), value)) pairs. Each entry is
// tested as a circuit; if it parses, it is stored as a circuit, otherwise
// as a plain value.
func importValues(store *Store, v Value) error {
	seq, ok := v.(Seq)
	if !ok {
		// Single value, store as-is
		store.PutValue(v)
		return nil
	}

	for _, item := range seq.Items {
		tag, ok := item.(Tag)
		if !ok {
			store.PutValue(item)
			continue
		}
		label, ok := tag.Label.(Text)
		if !ok || label.V != "entry" {
			store.PutValue(item)
			continue
		}
		payload, ok := tag.Payload.(Seq)
		if !ok || len(payload.Items) < 2 {
			store.PutValue(item)
			continue
		}
		qgidBytes, ok := payload.Items[0].(Bytes)
		if !ok || len(qgidBytes.V) < 32 {
			store.PutValue(item)
			continue
		}
		entryValue := payload.Items[1]

		var qgid [32]byte
		copy(qgid[:], qgidBytes.V[:32])

		// Try to parse as a circuit
		c, ok := CircuitFromValue(entryValue)
		if ok {
			store.circuits[qgid] = c
			store.values[qgid] = entryValue
		} else {
			store.values[qgid] = entryValue
		}
	}
	return nil
}

// Run executes the binary's entrypoint circuit.
func (r *Runner) Run(input *Matrix) (*Matrix, error) {
	c, ok := r.store.Get(r.binary.Entrypoint)
	if !ok {
		return nil, fmt.Errorf("entrypoint circuit not found")
	}
	return r.executor.Execute(c, input)
}

// RunWithValue executes with a Value input.
func (r *Runner) RunWithValue(input Value) (Value, error) {
	// Convert value to matrix if needed
	matrix, ok := MatrixFromValue(input)
	if !ok {
		// Try to interpret as identity
		matrix = Identity(1)
	}

	result, err := r.Run(matrix)
	if err != nil {
		return nil, err
	}

	return MatrixToValue(result), nil
}

// Name returns the binary name.
func (r *Runner) Name() string {
	return r.binary.Name
}

// Version returns the binary version.
func (r *Runner) Version() string {
	return r.binary.Version
}

// Entrypoint returns the entrypoint QGID.
func (r *Runner) Entrypoint() [32]byte {
	return r.binary.Entrypoint
}

// GetCircuit retrieves a circuit by QGID.
func (r *Runner) GetCircuit(id [32]byte) (Circuit, bool) {
	return r.store.Get(id)
}

// GetValue retrieves a value by QGID.
func (r *Runner) GetValue(id [32]byte) (Value, bool) {
	return r.store.GetValue(id)
}

// StoreSize returns the number of entries in the store.
func (r *Runner) StoreSize() int {
	return r.store.StoreSize()
}

// Embed creates an embedded binary from a store and entrypoint. It
// serializes every circuit and value in the store as a Seq of
// Tag("entry", Seq(Bytes(qgid), value)) pairs.
func Embed(store *Store, entrypoint [32]byte, name, version string) *EmbeddedBinary {
	var entries []Value

	// Collect all values (which includes circuit values stored via Put)
	for id, v := range store.values {
		qgidBytes := make([]byte, 32)
		copy(qgidBytes, id[:])
		entry := MakeTag(
			MakeText("entry"),
			MakeSeq(MakeBytes(qgidBytes), v),
		)
		entries = append(entries, entry)
	}

	var storeData []byte
	if len(entries) > 0 {
		storeSeq := MakeSeq(entries...)
		storeData = storeSeq.Encode()
	}

	return &EmbeddedBinary{
		Magic:      [4]byte{'Q', 'M', 'B', 0x01},
		Entrypoint: entrypoint,
		Name:       name,
		Version:    version,
		StoreData:  storeData,
	}
}

// StoreSize returns the total number of entries (circuits + values) in the
// store. Circuits that also have a value entry are counted once.
func (s *Store) StoreSize() int {
	return len(s.values)
}
