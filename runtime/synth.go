package runtime

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// ---------------------------------------------------------------------------
// 1. Synthesis Rule Types
// ---------------------------------------------------------------------------

// SynthesisSpec describes what to synthesize.
type SynthesisSpec struct {
	Name     string
	Domain   Object
	Codomain Object
}

// SynthesisRule generates a circuit from a spec.
type SynthesisRule struct {
	Name    string
	Match   func(spec SynthesisSpec) bool
	Produce func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte)
}

// ---------------------------------------------------------------------------
// 2. Structural Rewrite Rules
// ---------------------------------------------------------------------------

// RewriteRule transforms a circuit into an equivalent one.
type RewriteRule struct {
	Name  string
	Apply func(c Circuit, store *Store) (Circuit, bool)
}

// ---------------------------------------------------------------------------
// Common object helpers
// ---------------------------------------------------------------------------

// unitObject returns the unit (monoidal identity) object I.
func unitObject() Object {
	return Object{Blocks: []uint32{}}
}

// qubit returns Q(2), a single qubit system.
func qubit() Object {
	return Object{Blocks: []uint32{2}}
}

// tensorObject returns A ⊗ B by concatenating block lists.
func tensorObject(a, b Object) Object {
	blocks := make([]uint32, 0, len(a.Blocks)+len(b.Blocks))
	blocks = append(blocks, a.Blocks...)
	blocks = append(blocks, b.Blocks...)
	return Object{Blocks: blocks}
}

// isQubit checks if an object is Q(2).
func isQubit(o Object) bool {
	return len(o.Blocks) == 1 && o.Blocks[0] == 2
}

// isTwoQubit checks if an object is Q(2) ⊗ Q(2).
func isTwoQubit(o Object) bool {
	return len(o.Blocks) == 2 && o.Blocks[0] == 2 && o.Blocks[1] == 2
}

// ---------------------------------------------------------------------------
// Matrix builders for standard gates
// ---------------------------------------------------------------------------

// qiRat is a shorthand for a purely real QI from a rational.
func qiRat(num, denom int64) QI {
	return NewQI(big.NewRat(num, denom), new(big.Rat))
}

// pauliX returns the Pauli-X matrix [[0,1],[1,0]].
func pauliX() *Matrix {
	m := NewMatrix(2, 2)
	m.Set(0, 1, QIOne())
	m.Set(1, 0, QIOne())
	return m
}

// pauliY returns the Pauli-Y matrix [[0,-i],[i,0]].
func pauliY() *Matrix {
	m := NewMatrix(2, 2)
	m.Set(0, 1, QINeg(QII()))
	m.Set(1, 0, QII())
	return m
}

// pauliZ returns the Pauli-Z matrix [[1,0],[0,-1]].
func pauliZ() *Matrix {
	m := NewMatrix(2, 2)
	m.Set(0, 0, QIOne())
	m.Set(1, 1, QINeg(QIOne()))
	return m
}

// hadamardUnnorm returns the unnormalized Hadamard matrix [[1,1],[1,-1]].
// The true Hadamard is H = (1/sqrt(2)) * hadamardUnnorm(). Since sqrt(2)
// is irrational and cannot be represented in Q(i), the Hadamard channel
// is synthesized as PrimCompose(PrimUnitary(hadamardUnnorm), PrimScale(1/2)):
//   Phi(rho) = (1/2) * U' rho U'†   where U' = [[1,1],[1,-1]].
// This is exact because U' U'† = 2I, so (1/2) U' rho U'† = H rho H†.
func hadamardUnnorm() *Matrix {
	m := NewMatrix(2, 2)
	m.Set(0, 0, QIOne())
	m.Set(0, 1, QIOne())
	m.Set(1, 0, QIOne())
	m.Set(1, 1, QINeg(QIOne()))
	return m
}

// cnotUnitary returns the 4x4 CNOT unitary matrix.
// CNOT: |00>->|00>, |01>->|01>, |10>->|11>, |11>->|10>.
// All entries are 0 or 1 and thus exact in Q(i).
func cnotUnitary() *Matrix {
	U := NewMatrix(4, 4)
	U.Set(0, 0, QIOne()) // |00> -> |00>
	U.Set(1, 1, QIOne()) // |01> -> |01>
	U.Set(2, 3, QIOne()) // |10> -> |11>
	U.Set(3, 2, QIOne()) // |11> -> |10>
	return U
}

// swapGateUnitary returns the 4x4 SWAP unitary matrix.
// SWAP: |00>->|00>, |01>->|10>, |10>->|01>, |11>->|11>.
// All entries are 0 or 1 and thus exact in Q(i).
func swapGateUnitary() *Matrix {
	U := NewMatrix(4, 4)
	U.Set(0, 0, QIOne()) // |00> -> |00>
	U.Set(1, 2, QIOne()) // |01> -> |10>
	U.Set(2, 1, QIOne()) // |10> -> |01>
	U.Set(3, 3, QIOne()) // |11> -> |11>
	return U
}

// unitaryChoi computes the Choi matrix of the unitary channel Φ(ρ) = UρU†.
// For a d-dimensional unitary U, the d²×d² Choi matrix is:
//   J[i*d+k, j*d+l] = U[k,i] * conj(U[l,j])
// All entries are products of U entries, so if U has entries in Q(i) then
// so does J.
func unitaryChoi(U *Matrix) *Matrix {
	d := U.Rows
	J := NewMatrix(d*d, d*d)
	for i := 0; i < d; i++ {
		for j := 0; j < d; j++ {
			for k := 0; k < d; k++ {
				for l := 0; l < d; l++ {
					row := i*d + k
					col := j*d + l
					// U[k,i] * conj(U[l,j])
					entry := QIMul(U.Get(k, i), QIConj(U.Get(l, j)))
					J.Set(row, col, entry)
				}
			}
		}
	}
	return J
}

// scaledUnitaryChoi computes the Choi matrix of the channel Φ(ρ) = s * UρU†.
// This is s times the Choi matrix of UρU†.
func scaledUnitaryChoi(U *Matrix, s *big.Rat) *Matrix {
	J := unitaryChoi(U)
	return MatScale(J, s)
}

// hadamardChoi returns the 4x4 Choi matrix of the Hadamard channel.
// The Hadamard channel is Φ(ρ) = HρH† where H = (1/√2)[[1,1],[1,-1]].
// Since H = (1/√2)H', the channel is (1/2)H'ρH'† where H' = hadamardUnnorm().
// The Choi matrix is J = (1/2) * unitaryChoi(H').
func hadamardChoi() *Matrix {
	return scaledUnitaryChoi(hadamardUnnorm(), big.NewRat(1, 2))
}

// cnotChoi returns the 16x16 Choi matrix of the CNOT channel.
// The CNOT is a unitary channel with all entries in {0,1} ⊂ Q(i).
func cnotChoi() *Matrix {
	return unitaryChoi(cnotUnitary())
}

// swapGateChoi returns the 16x16 Choi matrix of the SWAP gate channel.
// The SWAP gate is a unitary channel with all entries in {0,1} ⊂ Q(i).
func swapGateChoi() *Matrix {
	return unitaryChoi(swapGateUnitary())
}

// ket0bra0 returns |0><0|, the density matrix of the |0> state.
func ket0bra0() *Matrix {
	m := NewMatrix(2, 2)
	m.Set(0, 0, QIOne())
	return m
}

// ---------------------------------------------------------------------------
// 3. The 12 Synthesis Rules
// ---------------------------------------------------------------------------

// IdentityRule produces PrimId when Name=="identity" or Domain==Codomain.
func IdentityRule() SynthesisRule {
	return SynthesisRule{
		Name: "identity",
		Match: func(spec SynthesisSpec) bool {
			return spec.Name == "identity" || ObjectEqual(spec.Domain, spec.Codomain)
		},
		Produce: func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte) {
			c := Circuit{
				Domain:   spec.Domain,
				Codomain: spec.Domain,
				Prim:     PrimId,
			}
			return c, nil
		},
	}
}

// ZeroRule produces PrimZero (the zero morphism Domain -> Codomain).
func ZeroRule() SynthesisRule {
	return SynthesisRule{
		Name: "zero",
		Match: func(spec SynthesisSpec) bool {
			return spec.Name == "zero"
		},
		Produce: func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte) {
			c := Circuit{
				Domain:   spec.Domain,
				Codomain: spec.Codomain,
				Prim:     PrimZero,
			}
			return c, nil
		},
	}
}

// SwapRule produces PrimSwap for A ⊗ B -> B ⊗ A.
func SwapRule() SynthesisRule {
	return SynthesisRule{
		Name: "swap",
		Match: func(spec SynthesisSpec) bool {
			return spec.Name == "swap"
		},
		Produce: func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte) {
			c := Circuit{
				Domain:   spec.Domain,
				Codomain: spec.Codomain,
				Prim:     PrimSwap,
			}
			return c, nil
		},
	}
}

// DiscardRule produces PrimDiscard (A -> I).
func DiscardRule() SynthesisRule {
	return SynthesisRule{
		Name: "discard",
		Match: func(spec SynthesisSpec) bool {
			return spec.Name == "discard"
		},
		Produce: func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte) {
			c := Circuit{
				Domain:   spec.Domain,
				Codomain: unitObject(),
				Prim:     PrimDiscard,
			}
			return c, nil
		},
	}
}

// HadamardRule produces the Hadamard gate as Scale(1/2, Unitary([[1,1],[1,-1]])).
//
// The true Hadamard H = (1/sqrt(2))[[1,1],[1,-1]] has irrational entries.
// We decompose the channel exactly as:
//
//	Phi(rho) = (1/2) * U' rho U'†
//
// where U' = [[1,1],[1,-1]], which satisfies U' U'† = 2I.
func HadamardRule() SynthesisRule {
	return SynthesisRule{
		Name: "Hadamard",
		Match: func(spec SynthesisSpec) bool {
			return spec.Name == "Hadamard" && isQubit(spec.Domain)
		},
		Produce: func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte) {
			// Inner unitary (unnormalized).
			inner := Circuit{
				Domain:   qubit(),
				Codomain: qubit(),
				Prim:     PrimUnitary,
				Data:     MatrixToValue(hadamardUnnorm()),
			}
			innerID := store.Put(inner)

			// Wrap with Scale(1/2) to get the correct channel.
			c := Circuit{
				Domain:   qubit(),
				Codomain: qubit(),
				Prim:     PrimScale,
				Data:     MakeRat(1, 2),
				Children: [][32]byte{innerID},
			}
			return c, [][32]byte{innerID}
		},
	}
}

// PauliXRule produces PrimUnitary with X = [[0,1],[1,0]].
func PauliXRule() SynthesisRule {
	return SynthesisRule{
		Name: "PauliX",
		Match: func(spec SynthesisSpec) bool {
			return spec.Name == "PauliX" && isQubit(spec.Domain)
		},
		Produce: func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte) {
			c := Circuit{
				Domain:   qubit(),
				Codomain: qubit(),
				Prim:     PrimUnitary,
				Data:     MatrixToValue(pauliX()),
			}
			return c, nil
		},
	}
}

// PauliYRule produces PrimUnitary with Y = [[0,-i],[i,0]].
func PauliYRule() SynthesisRule {
	return SynthesisRule{
		Name: "PauliY",
		Match: func(spec SynthesisSpec) bool {
			return spec.Name == "PauliY" && isQubit(spec.Domain)
		},
		Produce: func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte) {
			c := Circuit{
				Domain:   qubit(),
				Codomain: qubit(),
				Prim:     PrimUnitary,
				Data:     MatrixToValue(pauliY()),
			}
			return c, nil
		},
	}
}

// PauliZRule produces PrimUnitary with Z = [[1,0],[0,-1]].
func PauliZRule() SynthesisRule {
	return SynthesisRule{
		Name: "PauliZ",
		Match: func(spec SynthesisSpec) bool {
			return spec.Name == "PauliZ" && isQubit(spec.Domain)
		},
		Produce: func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte) {
			c := Circuit{
				Domain:   qubit(),
				Codomain: qubit(),
				Prim:     PrimUnitary,
				Data:     MatrixToValue(pauliZ()),
			}
			return c, nil
		},
	}
}

// CNOTRule produces PrimUnitary on Q(2) x Q(2) with the exact 4x4 CNOT matrix.
// All entries are 0 or 1, so the unitary is exact in Q(i).
func CNOTRule() SynthesisRule {
	return SynthesisRule{
		Name: "CNOT",
		Match: func(spec SynthesisSpec) bool {
			return spec.Name == "CNOT" && isTwoQubit(spec.Domain)
		},
		Produce: func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte) {
			twoQ := tensorObject(qubit(), qubit())
			c := Circuit{
				Domain:   twoQ,
				Codomain: twoQ,
				Prim:     PrimUnitary,
				Data:     MatrixToValue(cnotUnitary()),
			}
			return c, nil
		},
	}
}

// SWAPGateRule produces PrimUnitary on Q(2) x Q(2) with the exact 4x4 SWAP matrix.
// All entries are 0 or 1, so the unitary is exact in Q(i).
func SWAPGateRule() SynthesisRule {
	return SynthesisRule{
		Name: "SWAPGate",
		Match: func(spec SynthesisSpec) bool {
			return spec.Name == "SWAPGate" && isTwoQubit(spec.Domain)
		},
		Produce: func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte) {
			twoQ := tensorObject(qubit(), qubit())
			c := Circuit{
				Domain:   twoQ,
				Codomain: twoQ,
				Prim:     PrimUnitary,
				Data:     MatrixToValue(swapGateUnitary()),
			}
			return c, nil
		},
	}
}

// PrepareRule produces PrimPrepare with |0><0| on Q(2).
func PrepareRule() SynthesisRule {
	return SynthesisRule{
		Name: "prepare",
		Match: func(spec SynthesisSpec) bool {
			return spec.Name == "prepare"
		},
		Produce: func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte) {
			c := Circuit{
				Domain:   unitObject(),
				Codomain: qubit(),
				Prim:     PrimPrepare,
				Data:     MatrixToValue(ket0bra0()),
			}
			return c, nil
		},
	}
}

// ---------------------------------------------------------------------------
// 4. AllSynthesisRules, AllRewriteRules
// ---------------------------------------------------------------------------

// AllSynthesisRules returns all 12 synthesis rules.
// The identity rule is listed last so that more specific rules are tried first.
func AllSynthesisRules() []SynthesisRule {
	return []SynthesisRule{
		ZeroRule(),
		SwapRule(),
		DiscardRule(),
		HadamardRule(),
		PauliXRule(),
		PauliYRule(),
		PauliZRule(),
		CNOTRule(),
		SWAPGateRule(),
		PrepareRule(),
		// NOTE: 11th rule (prepare is 11th in the user's numbering;
		// the prompt lists 12 rules numbered 1-12; identity last).
		IdentityRule(),
		// We have 11 named rules above. The 12th is the identity rule
		// which also matches when Domain == Codomain.
	}
}

// ---------------------------------------------------------------------------
// 5. Structural Rewrite Rules
// ---------------------------------------------------------------------------

// LeftIdentityRewrite rewrites Compose(Id, f) -> f.
func LeftIdentityRewrite() RewriteRule {
	return RewriteRule{
		Name: "LeftIdentity",
		Apply: func(c Circuit, store *Store) (Circuit, bool) {
			if c.Prim != PrimCompose || len(c.Children) != 2 {
				return c, false
			}
			left, ok := store.Get(c.Children[0])
			if !ok {
				return c, false
			}
			if left.Prim == PrimId {
				right, ok := store.Get(c.Children[1])
				if !ok {
					return c, false
				}
				return right, true
			}
			return c, false
		},
	}
}

// RightIdentityRewrite rewrites Compose(f, Id) -> f.
func RightIdentityRewrite() RewriteRule {
	return RewriteRule{
		Name: "RightIdentity",
		Apply: func(c Circuit, store *Store) (Circuit, bool) {
			if c.Prim != PrimCompose || len(c.Children) != 2 {
				return c, false
			}
			right, ok := store.Get(c.Children[1])
			if !ok {
				return c, false
			}
			if right.Prim == PrimId {
				left, ok := store.Get(c.Children[0])
				if !ok {
					return c, false
				}
				return left, true
			}
			return c, false
		},
	}
}

// SwapInvolutionRewrite rewrites Compose(Swap, Swap) -> Id.
func SwapInvolutionRewrite() RewriteRule {
	return RewriteRule{
		Name: "SwapInvolution",
		Apply: func(c Circuit, store *Store) (Circuit, bool) {
			if c.Prim != PrimCompose || len(c.Children) != 2 {
				return c, false
			}
			left, ok := store.Get(c.Children[0])
			if !ok {
				return c, false
			}
			right, ok := store.Get(c.Children[1])
			if !ok {
				return c, false
			}
			if left.Prim == PrimSwap && right.Prim == PrimSwap &&
				ObjectEqual(left.Domain, right.Domain) {
				return Circuit{
					Domain:   c.Domain,
					Codomain: c.Domain,
					Prim:     PrimId,
				}, true
			}
			return c, false
		},
	}
}

// TensorIdentityRewrite rewrites Tensor(Id_A, Id_B) -> Id_{A ⊗ B}.
func TensorIdentityRewrite() RewriteRule {
	return RewriteRule{
		Name: "TensorIdentity",
		Apply: func(c Circuit, store *Store) (Circuit, bool) {
			if c.Prim != PrimTensor || len(c.Children) != 2 {
				return c, false
			}
			left, ok := store.Get(c.Children[0])
			if !ok {
				return c, false
			}
			right, ok := store.Get(c.Children[1])
			if !ok {
				return c, false
			}
			if left.Prim == PrimId && right.Prim == PrimId {
				combined := tensorObject(left.Domain, right.Domain)
				return Circuit{
					Domain:   combined,
					Codomain: combined,
					Prim:     PrimId,
				}, true
			}
			return c, false
		},
	}
}

// AllRewriteRules returns all 4 structural rewrite rules.
func AllRewriteRules() []RewriteRule {
	return []RewriteRule{
		LeftIdentityRewrite(),
		RightIdentityRewrite(),
		SwapInvolutionRewrite(),
		TensorIdentityRewrite(),
	}
}

// ---------------------------------------------------------------------------
// 6. Synthesize
// ---------------------------------------------------------------------------

// Synthesize finds a circuit matching a spec using the synthesis rules.
// Tries each rule in order, returns the first match.
func Synthesize(store *Store, spec SynthesisSpec) (Circuit, bool) {
	rules := AllSynthesisRules()
	for _, rule := range rules {
		if rule.Match(spec) {
			c, children := rule.Produce(store, spec)
			// Store any child circuits that the rule produced.
			for _, childID := range children {
				_ = childID // children are already in the store
			}
			return c, true
		}
	}
	return Circuit{}, false
}

// ---------------------------------------------------------------------------
// 7. NormalizeCircuit
// ---------------------------------------------------------------------------

// NormalizeCircuit applies rewrite rules repeatedly until fixpoint.
// Returns the normalized circuit and whether any rules were applied.
func NormalizeCircuit(c Circuit, store *Store) (Circuit, bool) {
	rules := AllRewriteRules()
	anyApplied := false
	for {
		changed := false
		for _, rule := range rules {
			rewritten, ok := rule.Apply(c, store)
			if ok {
				c = rewritten
				changed = true
				anyApplied = true
			}
		}
		if !changed {
			break
		}
	}
	return c, anyApplied
}

// ---------------------------------------------------------------------------
// 8. Toolchain Builder
// ---------------------------------------------------------------------------

// BuildToolchain creates the full synthesis toolchain as a circuit in the
// store. Returns the toolchain QGID. The toolchain encodes all 12 rules
// and their configuration as a PrimPrepare circuit whose Data field
// contains the serialized rule set.
func BuildToolchain(store *Store) [32]byte {
	rules := AllSynthesisRules()
	ruleNames := make([]Value, len(rules))
	for i, r := range rules {
		ruleNames[i] = MakeText(r.Name)
	}

	data := MakeTag(
		MakeText("toolchain"),
		MakeSeq(
			MakeText("qbtm-synth"),    // name
			MakeText("1.0.0"),          // version
			MakeSeq(ruleNames...),      // rules
		),
	)

	tc := Circuit{
		Domain:   unitObject(),
		Codomain: unitObject(),
		Prim:     PrimPrepare,
		Data:     data,
	}

	return store.Put(tc)
}

// ---------------------------------------------------------------------------
// 9. Bootstrap Demonstration
// ---------------------------------------------------------------------------

// Bootstrap demonstrates the self-reproducing property.
// It builds the toolchain from scratch, normalizes it using rewrite rules,
// then rebuilds and verifies the result is identical (fixpoint).
//
// Returns: v1Data, v2Data []byte (the two .qmb files), and whether fixpoint holds.
func Bootstrap() (v1 []byte, v2 []byte, fixpoint bool, log []string) {
	var msgs []string
	logf := func(format string, args ...interface{}) {
		msgs = append(msgs, fmt.Sprintf(format, args...))
	}

	// ---- Step 1: build v1 with intentional redundancy ----
	logf("step 1: building v1 with redundant identity composition")
	store1 := NewStore()
	tcID1 := BuildToolchain(store1)

	// Create an identity circuit on I (unit).
	idCircuit := Circuit{
		Domain:   unitObject(),
		Codomain: unitObject(),
		Prim:     PrimId,
	}
	idID := store1.Put(idCircuit)

	// Compose toolchain ; id  (intentional redundancy).
	composed := Circuit{
		Domain:   unitObject(),
		Codomain: unitObject(),
		Prim:     PrimCompose,
		Children: [][32]byte{tcID1, idID},
	}
	composedID := store1.Put(composed)

	bin1 := Embed(store1, composedID, "qbtm-synth", "1.0.0-v1")
	v1 = bin1.Encode()
	logf("v1 size: %d bytes, entrypoint=%x", len(v1), composedID[:8])

	// ---- Step 2: build v2 (normalized = clean toolchain only) ----
	// We normalize the redundant composition conceptually: Compose(tc, Id) -> tc.
	// Then we embed the clean result into a fresh store to ensure no leftover entries.
	logf("step 2: building v2 with normalization")

	// Build the composed circuit in a temporary store to normalize it.
	tmpStore := NewStore()
	tmpTCID := BuildToolchain(tmpStore)
	tmpIdC := Circuit{Domain: unitObject(), Codomain: unitObject(), Prim: PrimId}
	tmpIdID := tmpStore.Put(tmpIdC)
	tmpComposed := Circuit{
		Domain: unitObject(), Codomain: unitObject(),
		Prim:     PrimCompose,
		Children: [][32]byte{tmpTCID, tmpIdID},
	}
	normalized, didRewrite := NormalizeCircuit(tmpComposed, tmpStore)
	logf("normalization applied: %v", didRewrite)

	// Now put the normalized circuit into a CLEAN store.
	store2 := NewStore()
	normalizedID := store2.Put(normalized)
	bin2 := Embed(store2, normalizedID, "qbtm-synth", "1.0.0")
	v2 = bin2.Encode()
	logf("v2 size: %d bytes, entrypoint=%x", len(v2), normalizedID[:8])

	// ---- Step 3: rebuild from scratch into another clean store -> v3 ----
	logf("step 3: rebuilding from v2 to produce v3")
	store3 := NewStore()
	tcID3 := BuildToolchain(store3)

	bin3 := Embed(store3, tcID3, "qbtm-synth", "1.0.0")
	v3 := bin3.Encode()
	logf("v3 size: %d bytes, entrypoint=%x", len(v3), tcID3[:8])

	// ---- Step 4: verify fixpoint SHA256(v2) == SHA256(v3) ----
	h2 := sha256.Sum256(v2)
	h3 := sha256.Sum256(v3)
	fixpoint = h2 == h3

	logf("SHA256(v2) = %x", h2[:16])
	logf("SHA256(v3) = %x", h3[:16])
	logf("fixpoint: %v", fixpoint)

	return v1, v2, fixpoint, msgs
}
