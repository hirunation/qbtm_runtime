package runtime

import (
	"math/big"
	"testing"
)

// Value Tests

func TestMakeInt(t *testing.T) {
	v := MakeInt(42)
	if v.V.Int64() != 42 {
		t.Errorf("MakeInt(42) = %v, want 42", v.V)
	}
}

func TestMakeRat(t *testing.T) {
	v := MakeRat(1, 2)
	expected := big.NewRat(1, 2)
	if v.V.Cmp(expected) != 0 {
		t.Errorf("MakeRat(1, 2) = %v, want 1/2", v.V)
	}
}

func TestMakeText(t *testing.T) {
	v := MakeText("hello")
	if v.V != "hello" {
		t.Errorf("MakeText(hello) = %v, want hello", v.V)
	}
}

func TestMakeSeq(t *testing.T) {
	v := MakeSeq(MakeInt(1), MakeInt(2), MakeInt(3))
	if len(v.Items) != 3 {
		t.Errorf("MakeSeq length = %d, want 3", len(v.Items))
	}
}

func TestMakeTag(t *testing.T) {
	v := MakeTag(MakeText("label"), MakeInt(42))
	if label, ok := v.Label.(Text); !ok || label.V != "label" {
		t.Error("Tag label mismatch")
	}
}

func TestQGID(t *testing.T) {
	v := MakeInt(42)
	id := QGID(v)

	// ID should be non-zero
	allZero := true
	for _, b := range id {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("QGID should not be all zeros")
	}

	// Same value should produce same ID
	id2 := QGID(MakeInt(42))
	if id != id2 {
		t.Error("QGID should be deterministic")
	}
}

func TestEqual(t *testing.T) {
	tests := []struct {
		a, b   Value
		expect bool
	}{
		{MakeInt(42), MakeInt(42), true},
		{MakeInt(42), MakeInt(43), false},
		{MakeText("a"), MakeText("a"), true},
		{MakeText("a"), MakeText("b"), false},
		{MakeSeq(MakeInt(1)), MakeSeq(MakeInt(1)), true},
		{MakeNil(), MakeNil(), true},
	}

	for _, tt := range tests {
		got := Equal(tt.a, tt.b)
		if got != tt.expect {
			t.Errorf("Equal(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.expect)
		}
	}
}

// QI Tests

func TestQIAdd(t *testing.T) {
	a := NewQI(big.NewRat(1, 1), big.NewRat(2, 1))
	b := NewQI(big.NewRat(3, 1), big.NewRat(4, 1))
	c := QIAdd(a, b)

	if c.Re.Cmp(big.NewRat(4, 1)) != 0 {
		t.Errorf("Re = %v, want 4", c.Re)
	}
	if c.Im.Cmp(big.NewRat(6, 1)) != 0 {
		t.Errorf("Im = %v, want 6", c.Im)
	}
}

func TestQIMul(t *testing.T) {
	// (1+i)(1-i) = 1 - i^2 = 1 + 1 = 2
	a := NewQI(big.NewRat(1, 1), big.NewRat(1, 1))
	b := NewQI(big.NewRat(1, 1), big.NewRat(-1, 1))
	c := QIMul(a, b)

	if c.Re.Cmp(big.NewRat(2, 1)) != 0 {
		t.Errorf("Re = %v, want 2", c.Re)
	}
	if c.Im.Sign() != 0 {
		t.Errorf("Im = %v, want 0", c.Im)
	}
}

func TestQIInv(t *testing.T) {
	// 1/i = -i
	i := QII()
	inv, ok := QIInv(i)
	if !ok {
		t.Fatal("QIInv(i) failed")
	}

	if inv.Re.Sign() != 0 {
		t.Errorf("Re = %v, want 0", inv.Re)
	}
	if inv.Im.Cmp(big.NewRat(-1, 1)) != 0 {
		t.Errorf("Im = %v, want -1", inv.Im)
	}
}

func TestQIInvZero(t *testing.T) {
	_, ok := QIInv(QIZero())
	if ok {
		t.Error("QIInv(0) should fail")
	}
}

// Matrix Tests

func TestNewMatrix(t *testing.T) {
	m := NewMatrix(2, 3)
	if m.Rows != 2 || m.Cols != 3 {
		t.Errorf("Size = %dx%d, want 2x3", m.Rows, m.Cols)
	}
	if len(m.Data) != 6 {
		t.Errorf("Data length = %d, want 6", len(m.Data))
	}
}

func TestIdentity(t *testing.T) {
	m := Identity(3)
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			expected := QIZero()
			if i == j {
				expected = QIOne()
			}
			if !QIEqual(m.Get(i, j), expected) {
				t.Errorf("Identity[%d,%d] = %v, want %v", i, j, m.Get(i, j), expected)
			}
		}
	}
}

func TestMatMul(t *testing.T) {
	// I * I = I
	I := Identity(2)
	result := MatMul(I, I)
	if !MatrixEqual(result, I) {
		t.Error("I * I should equal I")
	}
}

func TestMatAdd(t *testing.T) {
	I := Identity(2)
	result := MatAdd(I, I)
	for i := 0; i < 2; i++ {
		expected := NewQI(big.NewRat(2, 1), big.NewRat(0, 1))
		if !QIEqual(result.Get(i, i), expected) {
			t.Errorf("I + I diagonal = %v, want 2", result.Get(i, i))
		}
	}
}

func TestDagger(t *testing.T) {
	// Create matrix [[1, i], [0, 1]]
	m := NewMatrix(2, 2)
	m.Set(0, 0, QIOne())
	m.Set(0, 1, QII())
	m.Set(1, 0, QIZero())
	m.Set(1, 1, QIOne())

	d := Dagger(m)

	// Dagger should be [[1, 0], [-i, 1]]
	if !QIEqual(d.Get(0, 0), QIOne()) {
		t.Error("Dagger[0,0] should be 1")
	}
	if !QIEqual(d.Get(0, 1), QIZero()) {
		t.Error("Dagger[0,1] should be 0")
	}
	if !QIEqual(d.Get(1, 0), QINeg(QII())) {
		t.Error("Dagger[1,0] should be -i")
	}
	if !QIEqual(d.Get(1, 1), QIOne()) {
		t.Error("Dagger[1,1] should be 1")
	}
}

func TestKronecker(t *testing.T) {
	I2 := Identity(2)
	result := Kronecker(I2, I2)

	if result.Rows != 4 || result.Cols != 4 {
		t.Errorf("Size = %dx%d, want 4x4", result.Rows, result.Cols)
	}

	// I ⊗ I = I4
	I4 := Identity(4)
	if !MatrixEqual(result, I4) {
		t.Error("I2 ⊗ I2 should equal I4")
	}
}

func TestTrace(t *testing.T) {
	I := Identity(3)
	tr := Trace(I)

	expected := NewQI(big.NewRat(3, 1), big.NewRat(0, 1))
	if !QIEqual(tr, expected) {
		t.Errorf("Trace(I3) = %v, want 3", tr)
	}
}

// Store Tests

func TestStore(t *testing.T) {
	store := NewStore()

	c := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimId,
	}

	id := store.Put(c)

	retrieved, ok := store.Get(id)
	if !ok {
		t.Fatal("Get failed")
	}

	if retrieved.Prim != PrimId {
		t.Errorf("Prim = %v, want Id", retrieved.Prim)
	}
}

// Executor Tests

func TestExecuteId(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	c := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimId,
	}

	input := Identity(2)
	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !MatrixEqual(result, input) {
		t.Error("Id should return input unchanged")
	}
}

func TestExecuteZero(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	c := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimZero,
	}

	input := Identity(2)
	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Should be zero matrix
	zero := NewMatrix(4, 4) // 2^2 = 4 for block size 2
	if !MatrixEqual(result, zero) {
		t.Error("Zero should return zero matrix")
	}
}

func TestExecuteCompose(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// Create id ; id
	id := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimId,
	}
	idID := store.Put(id)

	composed := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimCompose,
		Children: [][32]byte{idID, idID},
	}

	input := Identity(4)
	result, err := exec.Execute(composed, input)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !MatrixEqual(result, input) {
		t.Error("id ; id should return input unchanged")
	}
}

// Embed Tests

func TestEmbeddedBinaryEncodeDecode(t *testing.T) {
	var entrypoint [32]byte
	for i := 0; i < 32; i++ {
		entrypoint[i] = byte(i)
	}

	binary := EmbeddedBinary{
		Magic:      [4]byte{'Q', 'M', 'B', 0x01},
		Entrypoint: entrypoint,
		Name:       "test-binary",
		Version:    "1.0.0",
		StoreData:  []byte("test store data"),
	}

	encoded := binary.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Magic != binary.Magic {
		t.Errorf("Magic = %v, want %v", decoded.Magic, binary.Magic)
	}

	if decoded.Entrypoint != binary.Entrypoint {
		t.Error("Entrypoint mismatch")
	}

	if decoded.Name != binary.Name {
		t.Errorf("Name = %q, want %q", decoded.Name, binary.Name)
	}

	if decoded.Version != binary.Version {
		t.Errorf("Version = %q, want %q", decoded.Version, binary.Version)
	}

	if string(decoded.StoreData) != string(binary.StoreData) {
		t.Error("StoreData mismatch")
	}
}

func TestDecodeInvalidMagic(t *testing.T) {
	data := []byte{'X', 'Y', 'Z', 0x00}
	_, err := Decode(data)
	if err == nil {
		t.Error("Should fail for invalid magic")
	}
}

func TestDecodeTooShort(t *testing.T) {
	_, err := Decode([]byte{1, 2, 3})
	if err == nil {
		t.Error("Should fail for too short data")
	}
}

// Matrix encoding Tests

func TestMatrixToFromValue(t *testing.T) {
	m := Identity(2)
	v := MatrixToValue(m)

	parsed, ok := MatrixFromValue(v)
	if !ok {
		t.Fatal("MatrixFromValue failed")
	}

	if !MatrixEqual(parsed, m) {
		t.Error("Matrix round-trip failed")
	}
}

// Circuit encoding Tests

func TestCircuitToFromValue(t *testing.T) {
	c := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimId,
		Data:     MakeNil(),
		Children: [][32]byte{},
	}

	v := CircuitToValue(c)
	parsed, ok := CircuitFromValue(v)
	if !ok {
		t.Fatal("CircuitFromValue failed")
	}

	if parsed.Prim != c.Prim {
		t.Errorf("Prim = %v, want %v", parsed.Prim, c.Prim)
	}

	if !ObjectEqual(parsed.Domain, c.Domain) {
		t.Error("Domain mismatch")
	}
}

// Object Tests

func TestObjectEqual(t *testing.T) {
	a := Object{Blocks: []uint32{2, 3}}
	b := Object{Blocks: []uint32{2, 3}}
	c := Object{Blocks: []uint32{2, 4}}

	if !ObjectEqual(a, b) {
		t.Error("Equal objects should be equal")
	}

	if ObjectEqual(a, c) {
		t.Error("Different objects should not be equal")
	}
}

func TestObjectDim(t *testing.T) {
	// Q(2) has dimension 2^2 = 4
	obj := Object{Blocks: []uint32{2}}
	dim := objectDim(obj)
	if dim != 4 {
		t.Errorf("objectDim(Q(2)) = %d, want 4", dim)
	}

	// Unit has dimension 1
	unit := Object{Blocks: []uint32{}}
	dim = objectDim(unit)
	if dim != 1 {
		t.Errorf("objectDim(I) = %d, want 1", dim)
	}
}

// ============================================================
// TASK 1: Value decoder round-trip tests
// ============================================================

func TestDecodeValueInt(t *testing.T) {
	tests := []struct {
		name  string
		value Int
	}{
		{"zero", MakeInt(0)},
		{"small positive", MakeInt(42)},
		{"max small", MakeInt(0x3F)},
		{"large positive", MakeInt(1000)},
		{"negative", MakeInt(-7)},
		{"large negative", MakeInt(-999)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.value.Encode()
			decoded, consumed, err := decodeValue(encoded)
			if err != nil {
				t.Fatalf("decodeValue failed: %v", err)
			}
			if consumed != len(encoded) {
				t.Errorf("consumed %d bytes, want %d", consumed, len(encoded))
			}
			if !Equal(decoded, tt.value) {
				t.Errorf("round-trip failed: got %v, want %v", decoded, tt.value)
			}
		})
	}
}

func TestDecodeValueRat(t *testing.T) {
	tests := []struct {
		name  string
		value Rat
	}{
		{"zero", MakeRat(0, 1)},
		{"half", MakeRat(1, 2)},
		{"negative third", MakeRat(-1, 3)},
		{"big", MakeRat(12345, 67890)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := tt.value.Encode()
			decoded, consumed, err := decodeValue(encoded)
			if err != nil {
				t.Fatalf("decodeValue failed: %v", err)
			}
			if consumed != len(encoded) {
				t.Errorf("consumed %d bytes, want %d", consumed, len(encoded))
			}
			dRat, ok := decoded.(Rat)
			if !ok {
				t.Fatalf("expected Rat, got %T", decoded)
			}
			if dRat.V.Cmp(tt.value.V) != 0 {
				t.Errorf("round-trip failed: got %v, want %v", dRat.V, tt.value.V)
			}
		})
	}
}

func TestDecodeValueBytes(t *testing.T) {
	original := MakeBytes([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	encoded := original.Encode()
	decoded, consumed, err := decodeValue(encoded)
	if err != nil {
		t.Fatalf("decodeValue failed: %v", err)
	}
	if consumed != len(encoded) {
		t.Errorf("consumed %d, want %d", consumed, len(encoded))
	}
	if !Equal(decoded, original) {
		t.Error("Bytes round-trip failed")
	}
}

func TestDecodeValueText(t *testing.T) {
	original := MakeText("hello world")
	encoded := original.Encode()
	decoded, consumed, err := decodeValue(encoded)
	if err != nil {
		t.Fatalf("decodeValue failed: %v", err)
	}
	if consumed != len(encoded) {
		t.Errorf("consumed %d, want %d", consumed, len(encoded))
	}
	if !Equal(decoded, original) {
		t.Error("Text round-trip failed")
	}
}

func TestDecodeValueBool(t *testing.T) {
	for _, b := range []bool{true, false} {
		original := MakeBool(b)
		encoded := original.Encode()
		decoded, consumed, err := decodeValue(encoded)
		if err != nil {
			t.Fatalf("decodeValue(%v) failed: %v", b, err)
		}
		if consumed != 1 {
			t.Errorf("consumed %d, want 1", consumed)
		}
		if !Equal(decoded, original) {
			t.Errorf("Bool(%v) round-trip failed", b)
		}
	}
}

func TestDecodeValueNil(t *testing.T) {
	original := MakeNil()
	encoded := original.Encode()
	decoded, consumed, err := decodeValue(encoded)
	if err != nil {
		t.Fatalf("decodeValue failed: %v", err)
	}
	if consumed != 1 {
		t.Errorf("consumed %d, want 1", consumed)
	}
	if !Equal(decoded, original) {
		t.Error("Nil round-trip failed")
	}
}

func TestDecodeValueSeq(t *testing.T) {
	original := MakeSeq(MakeInt(1), MakeText("two"), MakeBool(true), MakeNil())
	encoded := original.Encode()
	decoded, consumed, err := decodeValue(encoded)
	if err != nil {
		t.Fatalf("decodeValue failed: %v", err)
	}
	if consumed != len(encoded) {
		t.Errorf("consumed %d, want %d", consumed, len(encoded))
	}
	if !Equal(decoded, original) {
		t.Error("Seq round-trip failed")
	}
}

func TestDecodeValueTag(t *testing.T) {
	original := MakeTag(MakeText("label"), MakeInt(42))
	encoded := original.Encode()
	decoded, consumed, err := decodeValue(encoded)
	if err != nil {
		t.Fatalf("decodeValue failed: %v", err)
	}
	if consumed != len(encoded) {
		t.Errorf("consumed %d, want %d", consumed, len(encoded))
	}
	if !Equal(decoded, original) {
		t.Error("Tag round-trip failed")
	}
}

func TestDecodeValueNestedComplex(t *testing.T) {
	// A complex nested structure: circuit-like value
	original := MakeTag(
		MakeText("circuit"),
		MakeSeq(
			MakeTag(MakeText("object"), MakeSeq(MakeInt(2))),
			MakeTag(MakeText("object"), MakeSeq(MakeInt(2))),
			MakeInt(0),
			MakeNil(),
			MakeSeq(),
		),
	)
	encoded := original.Encode()
	decoded, consumed, err := decodeValue(encoded)
	if err != nil {
		t.Fatalf("decodeValue failed: %v", err)
	}
	if consumed != len(encoded) {
		t.Errorf("consumed %d, want %d", consumed, len(encoded))
	}
	if !Equal(decoded, original) {
		t.Error("nested complex round-trip failed")
	}
}

func TestDecodeVarint(t *testing.T) {
	tests := []uint64{0, 1, 127, 128, 255, 300, 16384, 1000000}
	for _, n := range tests {
		encoded := encodeVarint(n)
		decoded, consumed, err := decodeVarint(encoded)
		if err != nil {
			t.Fatalf("decodeVarint(%d) failed: %v", n, err)
		}
		if consumed != len(encoded) {
			t.Errorf("decodeVarint(%d): consumed %d, want %d", n, consumed, len(encoded))
		}
		if decoded != n {
			t.Errorf("decodeVarint round-trip: got %d, want %d", decoded, n)
		}
	}
}

// ============================================================
// TASK 2: Store serialization round-trip tests
// ============================================================

func TestEmbedRoundTrip(t *testing.T) {
	store := NewStore()

	// Add a circuit
	c := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimId,
		Data:     MakeNil(),
		Children: [][32]byte{},
	}
	entrypoint := store.Put(c)

	// Add a plain value
	store.PutValue(MakeText("metadata"))

	// Embed
	binary := Embed(store, entrypoint, "test", "1.0")
	encoded := binary.Encode()

	// Decode
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Load into new store
	newStore := NewStore()
	if err := loadStoreData(newStore, decoded.StoreData); err != nil {
		t.Fatalf("loadStoreData failed: %v", err)
	}

	// Verify entrypoint circuit is present
	retrievedCircuit, ok := newStore.Get(entrypoint)
	if !ok {
		t.Fatal("entrypoint circuit not found in deserialized store")
	}
	if retrievedCircuit.Prim != PrimId {
		t.Errorf("Prim = %v, want Id", retrievedCircuit.Prim)
	}
	if !ObjectEqual(retrievedCircuit.Domain, c.Domain) {
		t.Error("Domain mismatch after round-trip")
	}
}

func TestEmbedEmptyStore(t *testing.T) {
	store := NewStore()
	var ep [32]byte
	binary := Embed(store, ep, "empty", "0.0")
	if len(binary.StoreData) != 0 {
		t.Errorf("empty store should produce no StoreData, got %d bytes", len(binary.StoreData))
	}
}

func TestStoreSize(t *testing.T) {
	store := NewStore()
	if store.StoreSize() != 0 {
		t.Errorf("empty store size = %d, want 0", store.StoreSize())
	}

	store.PutValue(MakeInt(1))
	if store.StoreSize() != 1 {
		t.Errorf("store size = %d, want 1", store.StoreSize())
	}

	// Put a circuit (also adds a value entry)
	store.Put(Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimId,
	})
	if store.StoreSize() != 2 {
		t.Errorf("store size = %d, want 2", store.StoreSize())
	}
}

func TestEmbedMultipleCircuits(t *testing.T) {
	store := NewStore()

	id1 := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimId,
		Data:     MakeNil(),
		Children: [][32]byte{},
	}
	id1ID := store.Put(id1)

	id2 := Circuit{
		Domain:   Object{Blocks: []uint32{3}},
		Codomain: Object{Blocks: []uint32{3}},
		Prim:     PrimId,
		Data:     MakeNil(),
		Children: [][32]byte{},
	}
	id2ID := store.Put(id2)

	composed := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimCompose,
		Data:     MakeNil(),
		Children: [][32]byte{id1ID, id1ID},
	}
	composedID := store.Put(composed)

	binary := Embed(store, composedID, "multi", "1.0")
	encoded := binary.Encode()

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	newStore := NewStore()
	if err := loadStoreData(newStore, decoded.StoreData); err != nil {
		t.Fatalf("loadStoreData failed: %v", err)
	}

	// All three circuits should be present
	if _, ok := newStore.Get(id1ID); !ok {
		t.Error("id1 circuit not found")
	}
	if _, ok := newStore.Get(id2ID); !ok {
		t.Error("id2 circuit not found")
	}
	if _, ok := newStore.Get(composedID); !ok {
		t.Error("composed circuit not found")
	}
}

// ============================================================
// TASK 3: Executor primitive tests
// ============================================================

func TestPrimName(t *testing.T) {
	tests := []struct {
		prim Prim
		name string
	}{
		{PrimId, "Id"},
		{PrimCompose, "Compose"},
		{PrimTensor, "Tensor"},
		{PrimSwap, "Swap"},
		{PrimInject, "Inject"},
		{PrimProject, "Project"},
		{PrimCopy, "Copy"},
		{PrimDelete, "Delete"},
		{PrimEncode, "Encode"},
		{PrimDecode, "Decode"},
		{PrimDiscard, "Discard"},
		{PrimTrace, "Trace"},
		{PrimKraus, "Kraus"},
		{PrimUnitary, "Unitary"},
		{PrimPrepare, "Prepare"},
		{PrimAdd, "Add"},
		{PrimScale, "Scale"},
		{PrimZero, "Zero"},
		{PrimAssert, "Assert"},
		{PrimWitness, "Witness"},
	}

	for _, tt := range tests {
		got := PrimName(tt.prim)
		if got != tt.name {
			t.Errorf("PrimName(%d) = %q, want %q", int(tt.prim), got, tt.name)
		}
	}
}

func TestExecuteSwap2x3(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// Swap Q(2)⊗Q(3) → Q(3)⊗Q(2)
	// dimA=2, dimB=3, total=6
	c := Circuit{
		Domain:   Object{Blocks: []uint32{2, 3}},
		Codomain: Object{Blocks: []uint32{3, 2}},
		Prim:     PrimSwap,
	}

	// Create a 6x6 input: |0,0⟩⟨0,0| = e_0 e_0^T
	input := NewMatrix(6, 6)
	input.Set(0, 0, QIOne())

	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute swap failed: %v", err)
	}

	// Swap|0,0⟩ = |0,0⟩ (both indices are 0, so swap is identity on this state)
	if !QIEqual(result.Get(0, 0), QIOne()) {
		t.Error("Swap|0,0⟩ should map to |0,0⟩")
	}

	// Test |0,1⟩ → |1,0⟩
	// |0,1⟩ in A⊗B has index 0*3+1 = 1
	// |1,0⟩ in B⊗A has index 1*2+0 = 2
	input2 := NewMatrix(6, 6)
	input2.Set(1, 1, QIOne())

	result2, err := exec.Execute(c, input2)
	if err != nil {
		t.Fatalf("Execute swap failed: %v", err)
	}

	// After swap, |0,1⟩ → |1,0⟩ which is index 2 in B⊗A
	if !QIEqual(result2.Get(2, 2), QIOne()) {
		t.Errorf("Swap|0,1⟩ should be at [2,2], got zero there")
	}
}

func TestExecuteSwapInvolution(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// Swap twice should be identity
	swap1 := Circuit{
		Domain:   Object{Blocks: []uint32{2, 3}},
		Codomain: Object{Blocks: []uint32{3, 2}},
		Prim:     PrimSwap,
	}
	id1 := store.Put(swap1)

	swap2 := Circuit{
		Domain:   Object{Blocks: []uint32{3, 2}},
		Codomain: Object{Blocks: []uint32{2, 3}},
		Prim:     PrimSwap,
	}
	id2 := store.Put(swap2)

	composed := Circuit{
		Domain:   Object{Blocks: []uint32{2, 3}},
		Codomain: Object{Blocks: []uint32{2, 3}},
		Prim:     PrimCompose,
		Children: [][32]byte{id1, id2},
	}

	input := Identity(6)
	result, err := exec.Execute(composed, input)
	if err != nil {
		t.Fatalf("Execute swap^2 failed: %v", err)
	}

	if !MatrixEqual(result, input) {
		t.Error("swap ; swap should be identity")
	}
}

func TestExecuteDiscard(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	c := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{}},
		Prim:     PrimDiscard,
	}

	input := Identity(4)
	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute discard failed: %v", err)
	}

	if result.Rows != 1 || result.Cols != 1 {
		t.Errorf("discard should produce 1x1, got %dx%d", result.Rows, result.Cols)
	}

	// Tr(I4) = 4
	expected := NewQI(big.NewRat(4, 1), big.NewRat(0, 1))
	if !QIEqual(result.Get(0, 0), expected) {
		t.Errorf("Tr(I4) = %v, want 4", result.Get(0, 0))
	}
}

func TestExecuteInject(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// Inject Q(2) → Q(2)⊕Q(1) = Object{2,1} with dim 4+1=5
	c := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2, 1}},
		Prim:     PrimInject,
	}

	input := Identity(4)
	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute inject failed: %v", err)
	}

	if result.Rows != 5 || result.Cols != 5 {
		t.Errorf("inject should produce 5x5, got %dx%d", result.Rows, result.Cols)
	}

	// Top-left 4x4 should be identity
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			expected := QIZero()
			if i == j {
				expected = QIOne()
			}
			if !QIEqual(result.Get(i, j), expected) {
				t.Errorf("inject[%d,%d] = %v, want %v", i, j, result.Get(i, j), expected)
			}
		}
	}

	// Last row and column should be zero
	for i := 0; i < 5; i++ {
		if !QIIsZero(result.Get(4, i)) {
			t.Errorf("inject[4,%d] should be 0", i)
		}
		if !QIIsZero(result.Get(i, 4)) {
			t.Errorf("inject[%d,4] should be 0", i)
		}
	}
}

func TestExecuteProject(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// Project Q(2)⊕Q(1) → Q(2), dim 5 → 4
	c := Circuit{
		Domain:   Object{Blocks: []uint32{2, 1}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimProject,
	}

	input := Identity(5)
	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute project failed: %v", err)
	}

	if result.Rows != 4 || result.Cols != 4 {
		t.Errorf("project should produce 4x4, got %dx%d", result.Rows, result.Cols)
	}

	// Should be I4
	if !MatrixEqual(result, Identity(4)) {
		t.Error("project(I5) should be I4")
	}
}

func TestExecuteInjectProjectRoundTrip(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// Project(Inject(ρ)) should equal ρ
	inject := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2, 1}},
		Prim:     PrimInject,
	}
	injectID := store.Put(inject)

	project := Circuit{
		Domain:   Object{Blocks: []uint32{2, 1}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimProject,
	}
	projectID := store.Put(project)

	composed := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimCompose,
		Children: [][32]byte{injectID, projectID},
	}

	input := Identity(4)
	result, err := exec.Execute(composed, input)
	if err != nil {
		t.Fatalf("Execute inject;project failed: %v", err)
	}

	if !MatrixEqual(result, input) {
		t.Error("project(inject(ρ)) should equal ρ")
	}
}

func TestExecuteCopy(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// Copy C(2) → C(2)⊗C(2), diagonal 2x2 → diagonal 4x4
	c := Circuit{
		Domain:   Object{Blocks: []uint32{1, 1}},
		Codomain: Object{Blocks: []uint32{1, 1, 1, 1}},
		Prim:     PrimCopy,
	}

	// Classical state: diag(1/3, 2/3)
	input := NewMatrix(2, 2)
	input.Set(0, 0, NewQI(big.NewRat(1, 3), new(big.Rat)))
	input.Set(1, 1, NewQI(big.NewRat(2, 3), new(big.Rat)))

	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute copy failed: %v", err)
	}

	if result.Rows != 4 || result.Cols != 4 {
		t.Errorf("copy should produce 4x4, got %dx%d", result.Rows, result.Cols)
	}

	// |0⟩ → |0,0⟩ at index 0*2+0=0, |1⟩ → |1,1⟩ at index 1*2+1=3
	if !QIEqual(result.Get(0, 0), NewQI(big.NewRat(1, 3), new(big.Rat))) {
		t.Errorf("copy[0,0] = %v, want 1/3", result.Get(0, 0))
	}
	if !QIEqual(result.Get(3, 3), NewQI(big.NewRat(2, 3), new(big.Rat))) {
		t.Errorf("copy[3,3] = %v, want 2/3", result.Get(3, 3))
	}
	// Off-diagonals at (1,1) and (2,2) should be zero
	if !QIIsZero(result.Get(1, 1)) {
		t.Errorf("copy[1,1] should be 0")
	}
	if !QIIsZero(result.Get(2, 2)) {
		t.Errorf("copy[2,2] should be 0")
	}
}

func TestExecuteDelete(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	c := Circuit{
		Domain:   Object{Blocks: []uint32{1, 1}},
		Codomain: Object{Blocks: []uint32{}},
		Prim:     PrimDelete,
	}

	input := NewMatrix(2, 2)
	input.Set(0, 0, NewQI(big.NewRat(1, 3), new(big.Rat)))
	input.Set(1, 1, NewQI(big.NewRat(2, 3), new(big.Rat)))

	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute delete failed: %v", err)
	}

	if result.Rows != 1 || result.Cols != 1 {
		t.Errorf("delete should produce 1x1, got %dx%d", result.Rows, result.Cols)
	}

	// Trace = 1/3 + 2/3 = 1
	if !QIEqual(result.Get(0, 0), QIOne()) {
		t.Errorf("delete trace = %v, want 1", result.Get(0, 0))
	}
}

func TestExecuteEncode(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	c := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimEncode,
	}

	input := Identity(4)
	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute encode failed: %v", err)
	}

	if !MatrixEqual(result, input) {
		t.Error("encode(I) should return I (diagonal preserved)")
	}
}

func TestExecuteDecode(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	c := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimDecode,
	}

	// Full density matrix with off-diagonals
	input := NewMatrix(2, 2)
	input.Set(0, 0, NewQI(big.NewRat(1, 2), new(big.Rat)))
	input.Set(0, 1, NewQI(big.NewRat(1, 4), new(big.Rat)))
	input.Set(1, 0, NewQI(big.NewRat(1, 4), new(big.Rat)))
	input.Set(1, 1, NewQI(big.NewRat(1, 2), new(big.Rat)))

	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute decode failed: %v", err)
	}

	// Off-diagonals should be zeroed out
	if !QIIsZero(result.Get(0, 1)) {
		t.Error("decode should zero out off-diagonals")
	}
	if !QIIsZero(result.Get(1, 0)) {
		t.Error("decode should zero out off-diagonals")
	}

	// Diagonals preserved
	if !QIEqual(result.Get(0, 0), NewQI(big.NewRat(1, 2), new(big.Rat))) {
		t.Error("decode should preserve diagonal")
	}
	if !QIEqual(result.Get(1, 1), NewQI(big.NewRat(1, 2), new(big.Rat))) {
		t.Error("decode should preserve diagonal")
	}
}

func TestExecuteTrace(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	c := Circuit{
		Domain:   Object{Blocks: []uint32{3}},
		Codomain: Object{Blocks: []uint32{}},
		Prim:     PrimTrace,
	}

	input := Identity(9)
	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute trace failed: %v", err)
	}

	if result.Rows != 1 || result.Cols != 1 {
		t.Errorf("trace should produce 1x1, got %dx%d", result.Rows, result.Cols)
	}

	expected := NewQI(big.NewRat(9, 1), new(big.Rat))
	if !QIEqual(result.Get(0, 0), expected) {
		t.Errorf("Tr(I9) = %v, want 9", result.Get(0, 0))
	}
}

func TestExecuteKraus(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// Single Kraus operator K = I (identity channel)
	K := Identity(2)

	c := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimKraus,
		Data: MakeTag(
			MakeText("kraus"),
			MakeSeq(MatrixToValue(K)),
		),
	}

	input := Identity(2)
	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute kraus failed: %v", err)
	}

	// K I K† = I * I * I = I
	if !MatrixEqual(result, input) {
		t.Error("Kraus with K=I should return input")
	}
}

func TestExecuteKrausDepolarizing(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// Two Kraus operators: K0 = (1/√2)I (but we use 1/2 for exact arithmetic)
	// and K1 = (1/√2)X (but we use 1/2 X for exact arithmetic)
	// This is a partial depolarizing-like channel
	half := big.NewRat(1, 2)

	K0 := NewMatrix(2, 2)
	K0.Set(0, 0, NewQI(half, new(big.Rat)))
	K0.Set(1, 1, NewQI(half, new(big.Rat)))

	K1 := NewMatrix(2, 2)
	K1.Set(0, 1, NewQI(half, new(big.Rat)))
	K1.Set(1, 0, NewQI(half, new(big.Rat)))

	c := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimKraus,
		Data: MakeTag(
			MakeText("kraus"),
			MakeSeq(MatrixToValue(K0), MatrixToValue(K1)),
		),
	}

	input := Identity(2)
	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute kraus failed: %v", err)
	}

	// K0 I K0† + K1 I K1† = (1/4)I + (1/4)I = (1/2)I
	expected := NewQI(big.NewRat(1, 2), new(big.Rat))
	if !QIEqual(result.Get(0, 0), expected) {
		t.Errorf("Kraus result[0,0] = %v, want 1/2", result.Get(0, 0))
	}
	if !QIEqual(result.Get(1, 1), expected) {
		t.Errorf("Kraus result[1,1] = %v, want 1/2", result.Get(1, 1))
	}
}

func TestExecuteAssert(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// Matching domain/codomain: should pass
	c := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimAssert,
	}

	input := Identity(4)
	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute assert failed: %v", err)
	}
	if !MatrixEqual(result, input) {
		t.Error("assert should return input unchanged")
	}

	// Mismatching: should fail
	c2 := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{3}},
		Prim:     PrimAssert,
	}
	_, err = exec.Execute(c2, input)
	if err == nil {
		t.Error("assert with mismatched types should fail")
	}
}

func TestExecuteWitness(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// Witness returns a prepared state from Data
	state := Identity(2)
	c := Circuit{
		Domain:   Object{Blocks: []uint32{}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimWitness,
		Data:     MatrixToValue(state),
	}

	input := Identity(1)
	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute witness failed: %v", err)
	}
	if !MatrixEqual(result, state) {
		t.Error("witness should return the prepared state")
	}
}

// ============================================================
// TASK 4: Swap correctness tests
// ============================================================

func TestSwapMatrixIsUnitary(t *testing.T) {
	// Build swap matrix for 2x3 and verify S S† = I
	dimA, dimB := 2, 3
	total := dimA * dimB
	S := NewMatrix(total, total)
	for i := 0; i < dimA; i++ {
		for j := 0; j < dimB; j++ {
			outIdx := j*dimA + i
			inIdx := i*dimB + j
			S.Set(outIdx, inIdx, QIOne())
		}
	}

	SSdag := MatMul(S, Dagger(S))
	if !MatrixEqual(SSdag, Identity(total)) {
		t.Error("S S† should be identity (swap is unitary)")
	}

	SdagS := MatMul(Dagger(S), S)
	if !MatrixEqual(SdagS, Identity(total)) {
		t.Error("S† S should be identity (swap is unitary)")
	}
}

func TestSwap2x2IsSymmetric(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// For 2x2 swap, swapping twice gives identity
	c := Circuit{
		Domain:   Object{Blocks: []uint32{2, 2}},
		Codomain: Object{Blocks: []uint32{2, 2}},
		Prim:     PrimSwap,
	}

	input := Identity(4)
	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute swap 2x2 failed: %v", err)
	}

	// For 2x2 swap applied twice, it should be identity
	result2, err := exec.Execute(c, result)
	if err != nil {
		t.Fatalf("Execute swap 2x2 second time failed: %v", err)
	}

	if !MatrixEqual(result2, input) {
		t.Error("swap^2 should be identity for same-dimension systems")
	}
}

func TestSwapSpecificStates(t *testing.T) {
	store := NewStore()
	exec := NewExecutor(store)

	// Swap Q(2)⊗Q(2): dimA=2, dimB=2, total=4
	c := Circuit{
		Domain:   Object{Blocks: []uint32{2, 2}},
		Codomain: Object{Blocks: []uint32{2, 2}},
		Prim:     PrimSwap,
	}

	// Test |1,0⟩⟨1,0| → |0,1⟩⟨0,1|
	// |1,0⟩ in A⊗B has index 1*2+0 = 2
	// |0,1⟩ in B⊗A has index 0*2+1 = 1
	input := NewMatrix(4, 4)
	input.Set(2, 2, QIOne())

	result, err := exec.Execute(c, input)
	if err != nil {
		t.Fatalf("Execute swap failed: %v", err)
	}

	if !QIEqual(result.Get(1, 1), QIOne()) {
		t.Error("Swap|1,0⟩ should give |0,1⟩ at index 1")
	}
	if !QIIsZero(result.Get(2, 2)) {
		t.Error("Original position should be zero after swap")
	}
}

// ============================================================
// Full integration test: embed + execute
// ============================================================

func TestFullEmbedExecuteRoundTrip(t *testing.T) {
	store := NewStore()

	// Build a unitary circuit: Pauli X gate
	X := NewMatrix(2, 2)
	X.Set(0, 1, QIOne())
	X.Set(1, 0, QIOne())

	pauliX := Circuit{
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{2}},
		Prim:     PrimUnitary,
		Data:     MatrixToValue(X),
		Children: [][32]byte{},
	}
	entrypoint := store.Put(pauliX)

	// Embed
	binary := Embed(store, entrypoint, "pauli-x", "1.0")
	encoded := binary.Encode()

	// Create runner from encoded binary
	runner, err := NewRunner(encoded)
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}

	if runner.Name() != "pauli-x" {
		t.Errorf("Name = %q, want pauli-x", runner.Name())
	}

	// Execute: X |0⟩⟨0| X† = |1⟩⟨1|
	input := NewMatrix(2, 2)
	input.Set(0, 0, QIOne())

	result, err := runner.Run(input)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Should flip: |0⟩⟨0| → |1⟩⟨1|
	if !QIIsZero(result.Get(0, 0)) {
		t.Error("[0,0] should be 0 after Pauli X")
	}
	if !QIEqual(result.Get(1, 1), QIOne()) {
		t.Error("[1,1] should be 1 after Pauli X")
	}
}
