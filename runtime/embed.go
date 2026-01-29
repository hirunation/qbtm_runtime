package runtime

import (
	"fmt"
)

// EmbeddedBinary represents a self-contained qmb binary.
type EmbeddedBinary struct {
	Magic      [4]byte   // "QMB\x01"
	Entrypoint [32]byte  // Main circuit QGID
	Name       string    // Binary name
	Version    string    // Version string
	StoreData  []byte    // Serialized store
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
	v, err := decodeValue(data)
	if err != nil {
		return err
	}

	// Import values
	return importValues(store, v)
}

// decodeValue decodes a Value from bytes (simplified).
func decodeValue(data []byte) (Value, error) {
	if len(data) == 0 {
		return MakeNil(), nil
	}

	// Simplified decoder
	switch data[0] {
	case 0x00:
		return MakeInt(0), nil
	case 0xF0:
		return MakeNil(), nil
	case 0xE0:
		return MakeBool(false), nil
	case 0xE1:
		return MakeBool(true), nil
	default:
		// For other types, return as bytes for now
		return MakeBytes(data), nil
	}
}

// importValues imports values into the store.
func importValues(store *Store, v Value) error {
	// If it's a sequence, import each item
	if seq, ok := v.(Seq); ok {
		for _, item := range seq.Items {
			store.PutValue(item)
		}
	} else {
		store.PutValue(v)
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

// Embed creates an embedded binary from a store and entrypoint.
func Embed(store *Store, entrypoint [32]byte, name, version string) *EmbeddedBinary {
	// Collect all values
	var storeData []byte

	// Simplified: just encode all circuit values
	// In a real implementation, this would serialize the full store

	return &EmbeddedBinary{
		Magic:      [4]byte{'Q', 'M', 'B', 0x01},
		Entrypoint: entrypoint,
		Name:       name,
		Version:    version,
		StoreData:  storeData,
	}
}
