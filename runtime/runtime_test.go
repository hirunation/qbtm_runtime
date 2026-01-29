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
