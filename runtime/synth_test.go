package runtime

import (
	"crypto/sha256"
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// Synthesis Rule Tests
// ---------------------------------------------------------------------------

func TestIdentityRuleName(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{
		Name:     "identity",
		Domain:   qubit(),
		Codomain: qubit(),
	}
	rule := IdentityRule()
	if !rule.Match(spec) {
		t.Fatal("IdentityRule should match name=identity")
	}
	c, _ := rule.Produce(store, spec)
	if c.Prim != PrimId {
		t.Errorf("expected PrimId, got %v", c.Prim)
	}
	if !ObjectEqual(c.Domain, qubit()) {
		t.Error("domain should be Q(2)")
	}
}

func TestIdentityRuleDomainEqualsCodomain(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{
		Name:     "something-else",
		Domain:   Object{Blocks: []uint32{3}},
		Codomain: Object{Blocks: []uint32{3}},
	}
	rule := IdentityRule()
	if !rule.Match(spec) {
		t.Fatal("IdentityRule should match when Domain == Codomain")
	}
	c, _ := rule.Produce(store, spec)
	if c.Prim != PrimId {
		t.Errorf("expected PrimId, got %v", c.Prim)
	}
}

func TestIdentityRuleNoMatch(t *testing.T) {
	spec := SynthesisSpec{
		Name:     "other",
		Domain:   Object{Blocks: []uint32{2}},
		Codomain: Object{Blocks: []uint32{3}},
	}
	if IdentityRule().Match(spec) {
		t.Error("IdentityRule should NOT match when name and types differ")
	}
}

func TestZeroRule(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{
		Name:     "zero",
		Domain:   qubit(),
		Codomain: Object{Blocks: []uint32{3}},
	}
	rule := ZeroRule()
	if !rule.Match(spec) {
		t.Fatal("ZeroRule should match name=zero")
	}
	c, _ := rule.Produce(store, spec)
	if c.Prim != PrimZero {
		t.Errorf("expected PrimZero, got %v", c.Prim)
	}
	if !ObjectEqual(c.Domain, qubit()) {
		t.Error("domain mismatch")
	}
	if !ObjectEqual(c.Codomain, Object{Blocks: []uint32{3}}) {
		t.Error("codomain mismatch")
	}
}

func TestSwapRule(t *testing.T) {
	store := NewStore()
	dom := tensorObject(qubit(), Object{Blocks: []uint32{3}})
	codom := tensorObject(Object{Blocks: []uint32{3}}, qubit())
	spec := SynthesisSpec{Name: "swap", Domain: dom, Codomain: codom}
	rule := SwapRule()
	if !rule.Match(spec) {
		t.Fatal("SwapRule should match name=swap")
	}
	c, _ := rule.Produce(store, spec)
	if c.Prim != PrimSwap {
		t.Errorf("expected PrimSwap, got %v", c.Prim)
	}
}

func TestDiscardRule(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{Name: "discard", Domain: qubit()}
	rule := DiscardRule()
	if !rule.Match(spec) {
		t.Fatal("DiscardRule should match")
	}
	c, _ := rule.Produce(store, spec)
	if c.Prim != PrimDiscard {
		t.Errorf("expected PrimDiscard, got %v", c.Prim)
	}
	if !ObjectEqual(c.Codomain, unitObject()) {
		t.Error("codomain should be unit")
	}
}

func TestHadamardRule(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{Name: "Hadamard", Domain: qubit(), Codomain: qubit()}
	rule := HadamardRule()
	if !rule.Match(spec) {
		t.Fatal("HadamardRule should match")
	}
	c, children := rule.Produce(store, spec)
	// The Hadamard is represented as Scale(1/2) applied to
	// Unitary([[1,1],[1,-1]]).
	if c.Prim != PrimScale {
		t.Errorf("expected PrimScale, got %v", c.Prim)
	}
	// Should have one child (the unnormalized unitary).
	if len(c.Children) != 1 {
		t.Fatalf("expected 1 child, got %d", len(c.Children))
	}
	if len(children) != 1 {
		t.Fatalf("expected 1 produced child QGID, got %d", len(children))
	}
	// Verify the child is the unnormalized Hadamard unitary.
	inner, ok := store.Get(c.Children[0])
	if !ok {
		t.Fatal("child circuit not found in store")
	}
	if inner.Prim != PrimUnitary {
		t.Errorf("child Prim = %v, want PrimUnitary", inner.Prim)
	}
	m, ok := MatrixFromValue(inner.Data)
	if !ok {
		t.Fatal("failed to parse unitary matrix")
	}
	if !MatrixEqual(m, hadamardUnnorm()) {
		t.Error("child unitary should be [[1,1],[1,-1]]")
	}
	// Scale factor should be 1/2.
	r, ok := c.Data.(Rat)
	if !ok {
		t.Fatal("scale data should be Rat")
	}
	if r.V.Cmp(big.NewRat(1, 2)) != 0 {
		t.Errorf("scale factor = %v, want 1/2", r.V)
	}
}

func TestHadamardRuleNoMatchWrongDomain(t *testing.T) {
	spec := SynthesisSpec{Name: "Hadamard", Domain: Object{Blocks: []uint32{3}}}
	if HadamardRule().Match(spec) {
		t.Error("HadamardRule should not match non-qubit domain")
	}
}

func TestPauliXRule(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{Name: "PauliX", Domain: qubit(), Codomain: qubit()}
	rule := PauliXRule()
	if !rule.Match(spec) {
		t.Fatal("PauliXRule should match")
	}
	c, _ := rule.Produce(store, spec)
	if c.Prim != PrimUnitary {
		t.Fatalf("expected PrimUnitary, got %v", c.Prim)
	}
	m, ok := MatrixFromValue(c.Data)
	if !ok {
		t.Fatal("failed to parse matrix")
	}
	if !MatrixEqual(m, pauliX()) {
		t.Error("matrix should be Pauli X")
	}
}

func TestPauliYRule(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{Name: "PauliY", Domain: qubit(), Codomain: qubit()}
	rule := PauliYRule()
	if !rule.Match(spec) {
		t.Fatal("PauliYRule should match")
	}
	c, _ := rule.Produce(store, spec)
	if c.Prim != PrimUnitary {
		t.Fatalf("expected PrimUnitary, got %v", c.Prim)
	}
	m, ok := MatrixFromValue(c.Data)
	if !ok {
		t.Fatal("failed to parse matrix")
	}
	if !MatrixEqual(m, pauliY()) {
		t.Error("matrix should be Pauli Y")
	}
}

func TestPauliZRule(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{Name: "PauliZ", Domain: qubit(), Codomain: qubit()}
	rule := PauliZRule()
	if !rule.Match(spec) {
		t.Fatal("PauliZRule should match")
	}
	c, _ := rule.Produce(store, spec)
	if c.Prim != PrimUnitary {
		t.Fatalf("expected PrimUnitary, got %v", c.Prim)
	}
	m, ok := MatrixFromValue(c.Data)
	if !ok {
		t.Fatal("failed to parse matrix")
	}
	if !MatrixEqual(m, pauliZ()) {
		t.Error("matrix should be Pauli Z")
	}
}

func TestCNOTRule(t *testing.T) {
	store := NewStore()
	twoQ := tensorObject(qubit(), qubit())
	spec := SynthesisSpec{Name: "CNOT", Domain: twoQ, Codomain: twoQ}
	rule := CNOTRule()
	if !rule.Match(spec) {
		t.Fatal("CNOTRule should match")
	}
	c, _ := rule.Produce(store, spec)
	if c.Prim != PrimUnitary {
		t.Fatalf("expected PrimUnitary, got %v", c.Prim)
	}
	m, ok := MatrixFromValue(c.Data)
	if !ok {
		t.Fatal("failed to parse unitary matrix")
	}
	if m.Rows != 4 || m.Cols != 4 {
		t.Fatalf("CNOT matrix size = %dx%d, want 4x4", m.Rows, m.Cols)
	}
	// CNOT is its own inverse: U*U = I
	prod := MatMul(m, m)
	if !MatrixEqual(prod, Identity(4)) {
		t.Error("CNOT should be an involution (U*U = I)")
	}
}

func TestSWAPGateRule(t *testing.T) {
	store := NewStore()
	twoQ := tensorObject(qubit(), qubit())
	spec := SynthesisSpec{Name: "SWAPGate", Domain: twoQ, Codomain: twoQ}
	rule := SWAPGateRule()
	if !rule.Match(spec) {
		t.Fatal("SWAPGateRule should match")
	}
	c, _ := rule.Produce(store, spec)
	if c.Prim != PrimUnitary {
		t.Fatalf("expected PrimUnitary, got %v", c.Prim)
	}
	m, ok := MatrixFromValue(c.Data)
	if !ok {
		t.Fatal("failed to parse unitary matrix")
	}
	if m.Rows != 4 || m.Cols != 4 {
		t.Fatalf("SWAP matrix size = %dx%d, want 4x4", m.Rows, m.Cols)
	}
	// SWAP is its own inverse: U*U = I
	prod := MatMul(m, m)
	if !MatrixEqual(prod, Identity(4)) {
		t.Error("SWAP should be an involution (U*U = I)")
	}
}

func TestPrepareRule(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{Name: "prepare", Domain: unitObject(), Codomain: qubit()}
	rule := PrepareRule()
	if !rule.Match(spec) {
		t.Fatal("PrepareRule should match")
	}
	c, _ := rule.Produce(store, spec)
	if c.Prim != PrimPrepare {
		t.Fatalf("expected PrimPrepare, got %v", c.Prim)
	}
	m, ok := MatrixFromValue(c.Data)
	if !ok {
		t.Fatal("failed to parse density matrix")
	}
	expected := ket0bra0()
	if !MatrixEqual(m, expected) {
		t.Error("prepare state should be |0><0|")
	}
}

// ---------------------------------------------------------------------------
// Hadamard Channel Correctness
// ---------------------------------------------------------------------------

func TestHadamardChannelOnRho(t *testing.T) {
	// Verify that applying the Hadamard channel via Choi to |0><0|
	// produces the expected result: H|0><0|H† = |+><+| = [[1/2,1/2],[1/2,1/2]].
	store := NewStore()
	spec := SynthesisSpec{Name: "Hadamard", Domain: qubit(), Codomain: qubit()}
	hc, _ := HadamardRule().Produce(store, spec)

	exec := NewExecutor(store)
	rho := ket0bra0() // |0><0|
	result, err := exec.Execute(hc, rho)
	if err != nil {
		t.Fatalf("execute Hadamard channel: %v", err)
	}
	// Expected: |+><+| = [[1/2, 1/2],[1/2, 1/2]]
	half := qiRat(1, 2)
	if result.Rows != 2 || result.Cols != 2 {
		t.Fatalf("result size = %dx%d, want 2x2", result.Rows, result.Cols)
	}
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			if !QIEqual(result.Get(i, j), half) {
				t.Errorf("result[%d,%d] = %v+%vi, want 1/2",
					i, j, result.Get(i, j).Re, result.Get(i, j).Im)
			}
		}
	}
}

func TestHadamardChannelOn1(t *testing.T) {
	// H|1><1|H† = |-><-| = [[1/2,-1/2],[-1/2,1/2]]
	store := NewStore()
	spec := SynthesisSpec{Name: "Hadamard", Domain: qubit(), Codomain: qubit()}
	hc, _ := HadamardRule().Produce(store, spec)

	exec := NewExecutor(store)
	rho := NewMatrix(2, 2)
	rho.Set(1, 1, QIOne()) // |1><1|

	result, err := exec.Execute(hc, rho)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	half := qiRat(1, 2)
	mhalf := qiRat(-1, 2)
	if !QIEqual(result.Get(0, 0), half) || !QIEqual(result.Get(0, 1), mhalf) ||
		!QIEqual(result.Get(1, 0), mhalf) || !QIEqual(result.Get(1, 1), half) {
		t.Errorf("H|1><1|H† incorrect: got [[%v,%v],[%v,%v]]",
			result.Get(0, 0).Re, result.Get(0, 1).Re,
			result.Get(1, 0).Re, result.Get(1, 1).Re)
	}
}

// ---------------------------------------------------------------------------
// Pauli Unitary Channel Correctness
// ---------------------------------------------------------------------------

func TestPauliXChannel(t *testing.T) {
	// X|0><0|X† = |1><1|
	store := NewStore()
	spec := SynthesisSpec{Name: "PauliX", Domain: qubit(), Codomain: qubit()}
	xc, _ := PauliXRule().Produce(store, spec)

	exec := NewExecutor(store)
	rho := ket0bra0()
	result, err := exec.Execute(xc, rho)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	expected := NewMatrix(2, 2)
	expected.Set(1, 1, QIOne())
	if !MatrixEqual(result, expected) {
		t.Error("X|0><0|X† should be |1><1|")
	}
}

func TestPauliZChannel(t *testing.T) {
	// Z|0><0|Z† = |0><0| (Z is diagonal, |0> is eigenstate)
	store := NewStore()
	spec := SynthesisSpec{Name: "PauliZ", Domain: qubit(), Codomain: qubit()}
	zc, _ := PauliZRule().Produce(store, spec)

	exec := NewExecutor(store)
	rho := ket0bra0()
	result, err := exec.Execute(zc, rho)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !MatrixEqual(result, rho) {
		t.Error("Z|0><0|Z† should be |0><0|")
	}
}

// ---------------------------------------------------------------------------
// Rewrite Rule Tests
// ---------------------------------------------------------------------------

func TestLeftIdentityRewrite(t *testing.T) {
	store := NewStore()
	f := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimUnitary,
		Data:     MatrixToValue(pauliX()),
	}
	fID := store.Put(f)

	idC := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimId,
	}
	idID := store.Put(idC)

	comp := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimCompose,
		Children: [][32]byte{idID, fID},
	}

	result, changed := LeftIdentityRewrite().Apply(comp, store)
	if !changed {
		t.Fatal("LeftIdentity should apply")
	}
	if result.Prim != PrimUnitary {
		t.Errorf("expected PrimUnitary, got %v", result.Prim)
	}
}

func TestRightIdentityRewrite(t *testing.T) {
	store := NewStore()
	f := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimUnitary,
		Data:     MatrixToValue(pauliZ()),
	}
	fID := store.Put(f)

	idC := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimId,
	}
	idID := store.Put(idC)

	comp := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimCompose,
		Children: [][32]byte{fID, idID},
	}

	result, changed := RightIdentityRewrite().Apply(comp, store)
	if !changed {
		t.Fatal("RightIdentity should apply")
	}
	if result.Prim != PrimUnitary {
		t.Errorf("expected PrimUnitary, got %v", result.Prim)
	}
}

func TestSwapInvolutionRewrite(t *testing.T) {
	store := NewStore()
	sw := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimSwap,
	}
	swID := store.Put(sw)

	comp := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimCompose,
		Children: [][32]byte{swID, swID},
	}

	result, changed := SwapInvolutionRewrite().Apply(comp, store)
	if !changed {
		t.Fatal("SwapInvolution should apply")
	}
	if result.Prim != PrimId {
		t.Errorf("expected PrimId, got %v", result.Prim)
	}
}

func TestTensorIdentityRewrite(t *testing.T) {
	store := NewStore()
	idA := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimId,
	}
	idAID := store.Put(idA)

	idB := Circuit{
		Domain:   Object{Blocks: []uint32{3}},
		Codomain: Object{Blocks: []uint32{3}},
		Prim:     PrimId,
	}
	idBID := store.Put(idB)

	tens := Circuit{
		Domain:   tensorObject(qubit(), Object{Blocks: []uint32{3}}),
		Codomain: tensorObject(qubit(), Object{Blocks: []uint32{3}}),
		Prim:     PrimTensor,
		Children: [][32]byte{idAID, idBID},
	}

	result, changed := TensorIdentityRewrite().Apply(tens, store)
	if !changed {
		t.Fatal("TensorIdentity should apply")
	}
	if result.Prim != PrimId {
		t.Errorf("expected PrimId, got %v", result.Prim)
	}
	expected := tensorObject(qubit(), Object{Blocks: []uint32{3}})
	if !ObjectEqual(result.Domain, expected) {
		t.Errorf("domain mismatch: %v", result.Domain)
	}
}

func TestRewriteNoMatchOnNonCompose(t *testing.T) {
	store := NewStore()
	c := Circuit{Prim: PrimId, Domain: qubit(), Codomain: qubit()}

	for _, rule := range AllRewriteRules() {
		_, changed := rule.Apply(c, store)
		if changed {
			t.Errorf("rule %q should not apply to a plain Id circuit", rule.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// NormalizeCircuit Tests
// ---------------------------------------------------------------------------

func TestNormalizeComposeWithId(t *testing.T) {
	store := NewStore()
	f := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimUnitary,
		Data:     MatrixToValue(pauliX()),
	}
	fID := store.Put(f)

	idC := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimId,
	}
	idID := store.Put(idC)

	comp := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimCompose,
		Children: [][32]byte{fID, idID},
	}

	result, changed := NormalizeCircuit(comp, store)
	if !changed {
		t.Fatal("NormalizeCircuit should apply at least one rewrite")
	}
	if result.Prim != PrimUnitary {
		t.Errorf("expected PrimUnitary, got %v", result.Prim)
	}
}

func TestNormalizeAlreadyNormal(t *testing.T) {
	store := NewStore()
	c := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimUnitary,
		Data:     MatrixToValue(pauliX()),
	}

	result, changed := NormalizeCircuit(c, store)
	if changed {
		t.Error("should not rewrite an already-normal circuit")
	}
	if result.Prim != c.Prim {
		t.Error("result should be unchanged")
	}
}

// ---------------------------------------------------------------------------
// Synthesize Tests
// ---------------------------------------------------------------------------

func TestSynthesizeIdentity(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{
		Name:     "identity",
		Domain:   qubit(),
		Codomain: qubit(),
	}
	c, ok := Synthesize(store, spec)
	if !ok {
		t.Fatal("Synthesize(identity) failed")
	}
	if c.Prim != PrimId {
		t.Errorf("expected PrimId, got %v", c.Prim)
	}
}

func TestSynthesizeHadamard(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{
		Name:     "Hadamard",
		Domain:   qubit(),
		Codomain: qubit(),
	}
	c, ok := Synthesize(store, spec)
	if !ok {
		t.Fatal("Synthesize(Hadamard) failed")
	}
	if c.Prim != PrimScale {
		t.Errorf("expected PrimScale, got %v", c.Prim)
	}
}

func TestSynthesizeCNOT(t *testing.T) {
	store := NewStore()
	twoQ := tensorObject(qubit(), qubit())
	spec := SynthesisSpec{
		Name:     "CNOT",
		Domain:   twoQ,
		Codomain: twoQ,
	}
	c, ok := Synthesize(store, spec)
	if !ok {
		t.Fatal("Synthesize(CNOT) failed")
	}
	if c.Prim != PrimUnitary {
		t.Errorf("expected PrimUnitary, got %v", c.Prim)
	}
}

func TestSynthesizeNoMatch(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{
		Name:     "nonexistent-gate",
		Domain:   Object{Blocks: []uint32{5}},
		Codomain: Object{Blocks: []uint32{7}},
	}
	_, ok := Synthesize(store, spec)
	if ok {
		t.Error("Synthesize should fail for unknown spec")
	}
}

func TestSynthesizeFallsBackToIdentity(t *testing.T) {
	// When name is not a known gate but Domain==Codomain, identity matches.
	store := NewStore()
	spec := SynthesisSpec{
		Name:     "unknown-gate",
		Domain:   qubit(),
		Codomain: qubit(),
	}
	c, ok := Synthesize(store, spec)
	if !ok {
		t.Fatal("Synthesize should fall back to identity")
	}
	if c.Prim != PrimId {
		t.Errorf("expected PrimId fallback, got %v", c.Prim)
	}
}

// ---------------------------------------------------------------------------
// AllSynthesisRules / AllRewriteRules Tests
// ---------------------------------------------------------------------------

func TestAllSynthesisRulesCount(t *testing.T) {
	rules := AllSynthesisRules()
	if len(rules) < 11 {
		t.Errorf("expected at least 11 synthesis rules, got %d", len(rules))
	}
}

func TestAllRewriteRulesCount(t *testing.T) {
	rules := AllRewriteRules()
	if len(rules) != 4 {
		t.Errorf("expected 4 rewrite rules, got %d", len(rules))
	}
}

func TestAllSynthesisRulesUniqueNames(t *testing.T) {
	rules := AllSynthesisRules()
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.Name] {
			t.Errorf("duplicate synthesis rule name: %q", r.Name)
		}
		seen[r.Name] = true
	}
}

// ---------------------------------------------------------------------------
// Toolchain Builder Tests
// ---------------------------------------------------------------------------

func TestBuildToolchain(t *testing.T) {
	store := NewStore()
	tcID := BuildToolchain(store)

	c, ok := store.Get(tcID)
	if !ok {
		t.Fatal("toolchain circuit not found in store")
	}
	if c.Prim != PrimPrepare {
		t.Errorf("expected PrimPrepare, got %v", c.Prim)
	}
	if !ObjectEqual(c.Domain, unitObject()) {
		t.Error("toolchain domain should be unit")
	}

	// Verify the data is a Tag("toolchain", ...).
	tag, ok := c.Data.(Tag)
	if !ok {
		t.Fatal("data should be a Tag")
	}
	label, ok := tag.Label.(Text)
	if !ok || label.V != "toolchain" {
		t.Errorf("label = %v, want 'toolchain'", tag.Label)
	}

	// Verify the payload contains name, version, and rules.
	payload, ok := tag.Payload.(Seq)
	if !ok || len(payload.Items) < 3 {
		t.Fatal("payload should be Seq with at least 3 items")
	}
	name, ok := payload.Items[0].(Text)
	if !ok || name.V != "qbtm-synth" {
		t.Errorf("name = %v, want 'qbtm-synth'", payload.Items[0])
	}
	version, ok := payload.Items[1].(Text)
	if !ok || version.V != "1.0.0" {
		t.Errorf("version = %v, want '1.0.0'", payload.Items[1])
	}
	rulesSeq, ok := payload.Items[2].(Seq)
	if !ok {
		t.Fatal("rules should be a Seq")
	}
	if len(rulesSeq.Items) < 11 {
		t.Errorf("expected at least 11 rule names, got %d", len(rulesSeq.Items))
	}
}

func TestBuildToolchainDeterministic(t *testing.T) {
	store1 := NewStore()
	id1 := BuildToolchain(store1)

	store2 := NewStore()
	id2 := BuildToolchain(store2)

	if id1 != id2 {
		t.Error("BuildToolchain should be deterministic (same QGID)")
	}
}

// ---------------------------------------------------------------------------
// Bootstrap Tests
// ---------------------------------------------------------------------------

func TestBootstrapFixpoint(t *testing.T) {
	v1, v2, fixpoint, log := Bootstrap()

	if len(v1) == 0 {
		t.Error("v1 should not be empty")
	}
	if len(v2) == 0 {
		t.Error("v2 should not be empty")
	}
	if !fixpoint {
		t.Error("bootstrap should reach fixpoint")
		for _, msg := range log {
			t.Logf("  %s", msg)
		}
	}

	// v1 should differ from v2 because v1 has the redundant composition.
	h1 := sha256.Sum256(v1)
	h2 := sha256.Sum256(v2)
	if h1 == h2 {
		t.Error("v1 and v2 should differ (v1 has redundancy)")
	}
}

func TestBootstrapLog(t *testing.T) {
	_, _, _, log := Bootstrap()
	if len(log) == 0 {
		t.Error("bootstrap should produce log messages")
	}
	// Check that the log mentions key steps.
	found := map[string]bool{}
	for _, msg := range log {
		if len(msg) > 5 && msg[:5] == "step " {
			found[msg[:6]] = true
		}
	}
	if !found["step 1"] {
		t.Error("log should mention step 1")
	}
	if !found["step 3"] {
		t.Error("log should mention step 3")
	}
}

// ---------------------------------------------------------------------------
// Store Round-tripping through .qmb Format
// ---------------------------------------------------------------------------

func TestStoreRoundTripIdentityCircuit(t *testing.T) {
	store := NewStore()
	c := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimId,
	}
	id := store.Put(c)

	bin := Embed(store, id, "test", "0.1")
	encoded := bin.Encode()

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Entrypoint != id {
		t.Error("entrypoint QGID mismatch after round-trip")
	}

	store2 := NewStore()
	if err := loadStoreData(store2, decoded.StoreData); err != nil {
		t.Fatalf("loadStoreData: %v", err)
	}

	c2, ok := store2.Get(id)
	if !ok {
		t.Fatal("circuit not found after round-trip")
	}
	if c2.Prim != PrimId {
		t.Errorf("Prim = %v, want PrimId", c2.Prim)
	}
	if !ObjectEqual(c2.Domain, qubit()) {
		t.Error("domain mismatch")
	}
}

func TestStoreRoundTripToolchain(t *testing.T) {
	store := NewStore()
	tcID := BuildToolchain(store)

	bin := Embed(store, tcID, "qbtm-synth", "1.0.0")
	encoded := bin.Encode()

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	store2 := NewStore()
	if err := loadStoreData(store2, decoded.StoreData); err != nil {
		t.Fatalf("loadStoreData: %v", err)
	}

	c2, ok := store2.Get(tcID)
	if !ok {
		t.Fatal("toolchain not found after round-trip")
	}
	if c2.Prim != PrimPrepare {
		t.Errorf("Prim = %v, want PrimPrepare", c2.Prim)
	}
}

func TestStoreRoundTripUnitaryCircuit(t *testing.T) {
	store := NewStore()
	c := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimUnitary,
		Data:     MatrixToValue(pauliX()),
	}
	id := store.Put(c)

	bin := Embed(store, id, "pauli-x", "1.0")
	encoded := bin.Encode()

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	store2 := NewStore()
	if err := loadStoreData(store2, decoded.StoreData); err != nil {
		t.Fatalf("loadStoreData: %v", err)
	}

	c2, ok := store2.Get(id)
	if !ok {
		t.Fatal("circuit not found after round-trip")
	}
	m, ok := MatrixFromValue(c2.Data)
	if !ok {
		t.Fatal("matrix data lost after round-trip")
	}
	if !MatrixEqual(m, pauliX()) {
		t.Error("matrix data corrupted after round-trip")
	}
}

func TestStoreRoundTripComposedCircuit(t *testing.T) {
	store := NewStore()

	xC := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimUnitary,
		Data:     MatrixToValue(pauliX()),
	}
	xID := store.Put(xC)

	zC := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimUnitary,
		Data:     MatrixToValue(pauliZ()),
	}
	zID := store.Put(zC)

	comp := Circuit{
		Domain:   qubit(),
		Codomain: qubit(),
		Prim:     PrimCompose,
		Children: [][32]byte{xID, zID},
	}
	compID := store.Put(comp)

	bin := Embed(store, compID, "XZ", "1.0")
	encoded := bin.Encode()

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	store2 := NewStore()
	if err := loadStoreData(store2, decoded.StoreData); err != nil {
		t.Fatalf("loadStoreData: %v", err)
	}

	c2, ok := store2.Get(compID)
	if !ok {
		t.Fatal("composed circuit not found after round-trip")
	}
	if c2.Prim != PrimCompose {
		t.Errorf("Prim = %v, want PrimCompose", c2.Prim)
	}
	if len(c2.Children) != 2 {
		t.Fatalf("children = %d, want 2", len(c2.Children))
	}

	// Check children survived.
	_, ok = store2.Get(c2.Children[0])
	if !ok {
		t.Error("child 0 not found after round-trip")
	}
	_, ok = store2.Get(c2.Children[1])
	if !ok {
		t.Error("child 1 not found after round-trip")
	}
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestUnitObject(t *testing.T) {
	u := unitObject()
	if len(u.Blocks) != 0 {
		t.Errorf("unitObject should have 0 blocks, got %d", len(u.Blocks))
	}
}

func TestQubit(t *testing.T) {
	q := qubit()
	if !isQubit(q) {
		t.Error("qubit() should satisfy isQubit()")
	}
}

func TestTensorObject(t *testing.T) {
	a := qubit()
	b := Object{Blocks: []uint32{3}}
	ab := tensorObject(a, b)
	if len(ab.Blocks) != 2 || ab.Blocks[0] != 2 || ab.Blocks[1] != 3 {
		t.Errorf("tensorObject = %v, want [2,3]", ab.Blocks)
	}
}

func TestIsTwoQubit(t *testing.T) {
	if !isTwoQubit(tensorObject(qubit(), qubit())) {
		t.Error("Q(2) x Q(2) should satisfy isTwoQubit()")
	}
	if isTwoQubit(qubit()) {
		t.Error("single qubit should not satisfy isTwoQubit()")
	}
}

func TestQiRat(t *testing.T) {
	q := qiRat(3, 7)
	if q.Re.Cmp(big.NewRat(3, 7)) != 0 {
		t.Errorf("Re = %v, want 3/7", q.Re)
	}
	if q.Im.Sign() != 0 {
		t.Error("Im should be 0")
	}
}

// ---------------------------------------------------------------------------
// Unitary Matrix Structural Tests
// ---------------------------------------------------------------------------

func TestHadamardUnnormStructure(t *testing.T) {
	U := hadamardUnnorm()
	// U U† = 2I
	Udag := Dagger(U)
	prod := MatMul(U, Udag)
	expected := NewMatrix(2, 2)
	expected.Set(0, 0, qiRat(2, 1))
	expected.Set(1, 1, qiRat(2, 1))
	if !MatrixEqual(prod, expected) {
		t.Error("hadamardUnnorm * hadamardUnnorm† should be 2I")
	}
}

func TestCNOTUnitaryIsUnitary(t *testing.T) {
	U := cnotUnitary()
	Udag := Dagger(U)
	prod := MatMul(U, Udag)
	if !MatrixEqual(prod, Identity(4)) {
		t.Error("CNOT should be unitary (U U† = I)")
	}
}

func TestSWAPUnitaryIsUnitary(t *testing.T) {
	U := swapGateUnitary()
	Udag := Dagger(U)
	prod := MatMul(U, Udag)
	if !MatrixEqual(prod, Identity(4)) {
		t.Error("SWAP should be unitary (U U† = I)")
	}
}

func TestPauliXIsUnitary(t *testing.T) {
	X := pauliX()
	Xdag := Dagger(X)
	prod := MatMul(X, Xdag)
	if !MatrixEqual(prod, Identity(2)) {
		t.Error("Pauli X should be unitary")
	}
}

func TestPauliYIsUnitary(t *testing.T) {
	Y := pauliY()
	Ydag := Dagger(Y)
	prod := MatMul(Y, Ydag)
	if !MatrixEqual(prod, Identity(2)) {
		t.Error("Pauli Y should be unitary")
	}
}

func TestPauliZIsUnitary(t *testing.T) {
	Z := pauliZ()
	Zdag := Dagger(Z)
	prod := MatMul(Z, Zdag)
	if !MatrixEqual(prod, Identity(2)) {
		t.Error("Pauli Z should be unitary")
	}
}

// ---------------------------------------------------------------------------
// Choi Matrix Tests (exercising the helper functions)
// ---------------------------------------------------------------------------

func TestHadamardChoiIsHermitian(t *testing.T) {
	J := hadamardChoi()
	Jdag := Dagger(J)
	if !MatrixEqual(J, Jdag) {
		t.Error("Hadamard Choi matrix should be Hermitian (J = J†)")
	}
}

func TestHadamardChoiTrace(t *testing.T) {
	// The Hadamard channel is (1/2) U' rho U'†. The Choi matrix trace
	// of this scaled channel is (1/2) * Tr(unitaryChoi(U')) = (1/2)*4 = 2.
	// However hadamardChoi() = (1/2) * unitaryChoi(U'), so Tr = (1/2)*4 = 2?
	// Actually Tr(unitaryChoi(U')) for 2x2 U' = Σ_i Σ_k |U'[k,i]|^2
	// = sum of squared magnitudes = 1+1+1+1 = 4. So (1/2)*4 = 2.
	// But for a TRACE-PRESERVING channel, the partial trace should be I.
	// The hadamard channel IS trace-preserving, so Tr(J) = dim = 2.
	J := hadamardChoi()
	tr := Trace(J)
	if !QIEqual(tr, qiRat(2, 1)) {
		t.Errorf("Tr(J_H) = %v+%vi, want 2", tr.Re, tr.Im)
	}
}

func TestCNOTChoiIsHermitian(t *testing.T) {
	J := cnotChoi()
	Jdag := Dagger(J)
	if !MatrixEqual(J, Jdag) {
		t.Error("CNOT Choi matrix should be Hermitian")
	}
}

func TestSWAPChoiIsHermitian(t *testing.T) {
	J := swapGateChoi()
	Jdag := Dagger(J)
	if !MatrixEqual(J, Jdag) {
		t.Error("SWAP Choi matrix should be Hermitian")
	}
}

func TestCNOTChoiTrace(t *testing.T) {
	J := cnotChoi()
	tr := Trace(J)
	// For a 4-dim unitary, Tr(Choi) = dim = 4
	if !QIEqual(tr, qiRat(4, 1)) {
		t.Errorf("Tr(J_CNOT) = %v+%vi, want 4", tr.Re, tr.Im)
	}
}

func TestSWAPChoiTrace(t *testing.T) {
	J := swapGateChoi()
	tr := Trace(J)
	if !QIEqual(tr, qiRat(4, 1)) {
		t.Errorf("Tr(J_SWAP) = %v+%vi, want 4", tr.Re, tr.Im)
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestSynthesizeZero(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{
		Name:     "zero",
		Domain:   qubit(),
		Codomain: Object{Blocks: []uint32{4}},
	}
	c, ok := Synthesize(store, spec)
	if !ok {
		t.Fatal("Synthesize(zero) failed")
	}
	if c.Prim != PrimZero {
		t.Errorf("expected PrimZero, got %v", c.Prim)
	}
}

func TestSynthesizeDiscard(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{
		Name:   "discard",
		Domain: qubit(),
	}
	c, ok := Synthesize(store, spec)
	if !ok {
		t.Fatal("Synthesize(discard) failed")
	}
	if c.Prim != PrimDiscard {
		t.Errorf("expected PrimDiscard, got %v", c.Prim)
	}
}

func TestSynthesizePrepare(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{
		Name:     "prepare",
		Domain:   unitObject(),
		Codomain: qubit(),
	}
	c, ok := Synthesize(store, spec)
	if !ok {
		t.Fatal("Synthesize(prepare) failed")
	}
	if c.Prim != PrimPrepare {
		t.Errorf("expected PrimPrepare, got %v", c.Prim)
	}
}

func TestSynthesizeSwap(t *testing.T) {
	store := NewStore()
	spec := SynthesisSpec{
		Name:     "swap",
		Domain:   tensorObject(qubit(), qubit()),
		Codomain: tensorObject(qubit(), qubit()),
	}
	c, ok := Synthesize(store, spec)
	if !ok {
		t.Fatal("Synthesize(swap) failed")
	}
	if c.Prim != PrimSwap {
		t.Errorf("expected PrimSwap, got %v", c.Prim)
	}
}

func TestSynthesizeSWAPGate(t *testing.T) {
	store := NewStore()
	twoQ := tensorObject(qubit(), qubit())
	spec := SynthesisSpec{
		Name:     "SWAPGate",
		Domain:   twoQ,
		Codomain: twoQ,
	}
	c, ok := Synthesize(store, spec)
	if !ok {
		t.Fatal("Synthesize(SWAPGate) failed")
	}
	if c.Prim != PrimUnitary {
		t.Errorf("expected PrimUnitary, got %v", c.Prim)
	}
}

func TestSynthesizeAllPaulis(t *testing.T) {
	store := NewStore()
	for _, name := range []string{"PauliX", "PauliY", "PauliZ"} {
		spec := SynthesisSpec{
			Name:     name,
			Domain:   qubit(),
			Codomain: qubit(),
		}
		c, ok := Synthesize(store, spec)
		if !ok {
			t.Fatalf("Synthesize(%s) failed", name)
		}
		if c.Prim != PrimUnitary {
			t.Errorf("Synthesize(%s): expected PrimUnitary, got %v", name, c.Prim)
		}
	}
}
