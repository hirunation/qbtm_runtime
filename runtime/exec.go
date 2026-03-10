package runtime

import (
	"fmt"
)

// Prim is the primitive type for circuits.
type Prim int

const (
	PrimId Prim = iota
	PrimCompose
	PrimTensor
	PrimSwap
	PrimBisum
	PrimInject
	PrimProject
	PrimCopy
	PrimDelete
	PrimEncode
	PrimDecode
	PrimDiscard
	PrimTrace
	PrimChoi
	PrimKraus
	PrimUnitary
	PrimInstrument
	PrimBranch
	PrimPrepare
	PrimAdd
	PrimScale
	PrimZero
	PrimAssert
	PrimWitness
)

// PrimName returns a human-readable string for a Prim constant.
func PrimName(p Prim) string {
	switch p {
	case PrimId:
		return "Id"
	case PrimCompose:
		return "Compose"
	case PrimTensor:
		return "Tensor"
	case PrimSwap:
		return "Swap"
	case PrimBisum:
		return "Bisum"
	case PrimInject:
		return "Inject"
	case PrimProject:
		return "Project"
	case PrimCopy:
		return "Copy"
	case PrimDelete:
		return "Delete"
	case PrimEncode:
		return "Encode"
	case PrimDecode:
		return "Decode"
	case PrimDiscard:
		return "Discard"
	case PrimTrace:
		return "Trace"
	case PrimChoi:
		return "Choi"
	case PrimKraus:
		return "Kraus"
	case PrimUnitary:
		return "Unitary"
	case PrimInstrument:
		return "Instrument"
	case PrimBranch:
		return "Branch"
	case PrimPrepare:
		return "Prepare"
	case PrimAdd:
		return "Add"
	case PrimScale:
		return "Scale"
	case PrimZero:
		return "Zero"
	case PrimAssert:
		return "Assert"
	case PrimWitness:
		return "Witness"
	default:
		return fmt.Sprintf("Prim(%d)", int(p))
	}
}

// Circuit represents a quantum circuit.
type Circuit struct {
	Domain   Object
	Codomain Object
	Prim     Prim
	Data     Value
	Children [][32]byte
}

// Object represents a C*-algebra type (block signature).
type Object struct {
	Blocks []uint32
}

// Store holds circuits by their QGID.
type Store struct {
	circuits map[[32]byte]Circuit
	values   map[[32]byte]Value
}

// NewStore creates a new store.
func NewStore() *Store {
	return &Store{
		circuits: make(map[[32]byte]Circuit),
		values:   make(map[[32]byte]Value),
	}
}

// Get retrieves a circuit by QGID.
func (s *Store) Get(id [32]byte) (Circuit, bool) {
	c, ok := s.circuits[id]
	return c, ok
}

// Put stores a circuit and returns its QGID.
func (s *Store) Put(c Circuit) [32]byte {
	v := CircuitToValue(c)
	id := QGID(v)
	s.circuits[id] = c
	s.values[id] = v
	return id
}

// GetValue retrieves a value by QGID.
func (s *Store) GetValue(id [32]byte) (Value, bool) {
	v, ok := s.values[id]
	return v, ok
}

// PutValue stores a value and returns its QGID.
func (s *Store) PutValue(v Value) [32]byte {
	id := QGID(v)
	s.values[id] = v
	return id
}

// Executor executes circuits.
type Executor struct {
	store *Store
}

// NewExecutor creates a new executor.
func NewExecutor(store *Store) *Executor {
	return &Executor{store: store}
}

// Execute executes a circuit on an input state.
// For quantum circuits, input is a density matrix.
func (e *Executor) Execute(c Circuit, input *Matrix) (*Matrix, error) {
	switch c.Prim {
	case PrimId:
		return input.Clone(), nil

	case PrimCompose:
		if len(c.Children) != 2 {
			return nil, fmt.Errorf("compose requires 2 children")
		}
		f, ok := e.store.Get(c.Children[0])
		if !ok {
			return nil, fmt.Errorf("child 0 not found")
		}
		g, ok := e.store.Get(c.Children[1])
		if !ok {
			return nil, fmt.Errorf("child 1 not found")
		}
		intermediate, err := e.Execute(f, input)
		if err != nil {
			return nil, err
		}
		return e.Execute(g, intermediate)

	case PrimTensor:
		if len(c.Children) != 2 {
			return nil, fmt.Errorf("tensor requires 2 children")
		}
		// For tensor product, apply each subcircuit to its portion
		// Simplified: just return Kronecker of results applied to identity
		f, ok := e.store.Get(c.Children[0])
		if !ok {
			return nil, fmt.Errorf("child 0 not found")
		}
		g, ok := e.store.Get(c.Children[1])
		if !ok {
			return nil, fmt.Errorf("child 1 not found")
		}
		// Compute f on identity and g on identity, then Kronecker
		fDim := objectDim(f.Domain)
		gDim := objectDim(g.Domain)
		fId := Identity(fDim)
		gId := Identity(gDim)
		fResult, err := e.Execute(f, fId)
		if err != nil {
			return nil, err
		}
		gResult, err := e.Execute(g, gId)
		if err != nil {
			return nil, err
		}
		return Kronecker(fResult, gResult), nil

	case PrimSwap:
		// Swap acts by permutation: A⊗B → B⊗A
		return e.applySwap(c.Domain, c.Codomain, input)

	case PrimDiscard:
		// Discard traces out the entire system, returning Tr(ρ) as a 1x1 matrix.
		// This is the trace-out-everything case. For partial trace over a
		// subsystem, use a composition of discard with tensor.
		return e.applyDiscard(c.Domain, input)

	case PrimInject:
		// Inclusion into biproduct: maps A → A⊕B by padding with zeros.
		return e.applyInject(c.Domain, c.Codomain, input)

	case PrimProject:
		// Projection from biproduct: maps A⊕B → A by truncation.
		return e.applyProject(c.Domain, c.Codomain, input)

	case PrimCopy:
		// Classical copying: maps C(k) → C(k)⊗C(k).
		// On diagonal density matrices, duplicates the diagonal.
		return e.applyCopy(c.Domain, input)

	case PrimDelete:
		// Classical deletion: maps C(k) → I (unit).
		// Returns sum of diagonal entries as a 1x1 matrix (trace).
		return e.applyDelete(input)

	case PrimEncode:
		// Classical-to-quantum encoding: maps C(k) → Q(k).
		// Takes a diagonal (classical) density matrix and returns it as a
		// full quantum density matrix (which is the same matrix).
		return e.applyEncode(c.Domain, input)

	case PrimDecode:
		// Quantum-to-classical decoding: maps Q(k) → C(k).
		// Measures in the computational basis by extracting the diagonal.
		return e.applyDecode(c.Domain, input)

	case PrimTrace:
		// Quantum trace: maps Q(n) → I, returns Tr(ρ) as a 1x1 matrix.
		return e.applyTrace(input)

	case PrimKraus:
		// Kraus representation: Φ(ρ) = Σ_k K_k ρ K_k†
		return e.applyKraus(c, input)

	case PrimZero:
		// Zero map returns zero matrix
		outDim := objectDim(c.Codomain)
		return NewMatrix(outDim, outDim), nil

	case PrimUnitary:
		// Apply unitary: U ρ U†
		return e.applyUnitary(c, input)

	case PrimChoi:
		// Apply via Choi matrix
		return e.applyChoi(c, input)

	case PrimPrepare:
		// Prepare a fixed state
		return e.applyPrepare(c)

	case PrimAdd:
		if len(c.Children) != 2 {
			return nil, fmt.Errorf("add requires 2 children")
		}
		f, ok := e.store.Get(c.Children[0])
		if !ok {
			return nil, fmt.Errorf("child 0 not found")
		}
		g, ok := e.store.Get(c.Children[1])
		if !ok {
			return nil, fmt.Errorf("child 1 not found")
		}
		fResult, err := e.Execute(f, input)
		if err != nil {
			return nil, err
		}
		gResult, err := e.Execute(g, input)
		if err != nil {
			return nil, err
		}
		return MatAdd(fResult, gResult), nil

	case PrimScale:
		if len(c.Children) != 1 {
			return nil, fmt.Errorf("scale requires 1 child")
		}
		// Get scale factor from data
		r, ok := c.Data.(Rat)
		if !ok {
			return nil, fmt.Errorf("scale data must be Rat")
		}
		child, ok := e.store.Get(c.Children[0])
		if !ok {
			return nil, fmt.Errorf("child not found")
		}
		result, err := e.Execute(child, input)
		if err != nil {
			return nil, err
		}
		return MatScale(result, r.V), nil

	case PrimAssert:
		// Type assertion: returns input unchanged if domain matches codomain.
		if !ObjectEqual(c.Domain, c.Codomain) {
			return nil, fmt.Errorf("assert: domain %v does not match codomain %v",
				c.Domain.Blocks, c.Codomain.Blocks)
		}
		return input.Clone(), nil

	case PrimWitness:
		// Witness: returns a prepared state, like Prepare.
		// The witness state is stored in Data.
		return e.applyPrepare(c)

	default:
		return nil, fmt.Errorf("unsupported primitive: %s (%d)", PrimName(c.Prim), int(c.Prim))
	}
}

// applySwap applies a swap operation on a bipartite system A⊗B → B⊗A.
//
// The domain must have exactly 2 blocks [a, b] representing Q(a)⊗Q(b).
// The swap permutation matrix S satisfies S|i,j⟩ = |j,i⟩, where i indexes
// system A (dimension a) and j indexes system B (dimension b).
//
// The matrix element S[j*dimA+i, i*dimB+j] = 1 for all valid i,j.
// The channel maps ρ ↦ S ρ S†.
func (e *Executor) applySwap(domain, codomain Object, input *Matrix) (*Matrix, error) {
	dimA, dimB, err := bipartiteDims(domain, codomain)
	if err != nil {
		// Fallback: if we cannot determine the split, return identity
		n := objectDim(domain)
		return MatMul(MatMul(Identity(n), input), Identity(n)), nil
	}

	totalDim := dimA * dimB

	// Build swap permutation matrix S where S|i,j⟩ = |j,i⟩.
	// Input basis ordering: |i⟩⊗|j⟩ has index i*dimB + j  (A⊗B)
	// Output basis ordering: |j⟩⊗|i⟩ has index j*dimA + i  (B⊗A)
	// So S[j*dimA+i, i*dimB+j] = 1
	S := NewMatrix(totalDim, totalDim)
	for i := 0; i < dimA; i++ {
		for j := 0; j < dimB; j++ {
			outIdx := j*dimA + i
			inIdx := i*dimB + j
			S.Set(outIdx, inIdx, QIOne())
		}
	}

	// Apply as S ρ S†
	Sdag := Dagger(S)
	return MatMul(MatMul(S, input), Sdag), nil
}

// bipartiteDims extracts the dimensions of the two subsystems from a
// bipartite domain. The domain should have exactly 2 blocks [a, b],
// giving dimA = a and dimB = b. If it does not, the codomain is used
// as a hint (it should have blocks [b, a]).
func bipartiteDims(domain, codomain Object) (dimA, dimB int, err error) {
	if len(domain.Blocks) == 2 {
		return int(domain.Blocks[0]), int(domain.Blocks[1]), nil
	}
	// Try codomain as hint: codomain should be [b, a]
	if len(codomain.Blocks) == 2 {
		return int(codomain.Blocks[1]), int(codomain.Blocks[0]), nil
	}
	return 0, 0, fmt.Errorf("swap: cannot determine bipartite split from blocks %v", domain.Blocks)
}

// applyDiscard applies a discard operation (full trace).
// This is the trace-out-everything case: maps Q(n) → I by returning
// Tr(ρ) as a 1x1 matrix (scalar channel).
func (e *Executor) applyDiscard(domain Object, input *Matrix) (*Matrix, error) {
	tr := Trace(input)
	result := NewMatrix(1, 1)
	result.Set(0, 0, tr)
	return result, nil
}

// applyInject applies injection into a biproduct: A → A⊕B.
// The output is a block-diagonal matrix with the input in the top-left
// block and zeros in the bottom-right block.
func (e *Executor) applyInject(domain, codomain Object, input *Matrix) (*Matrix, error) {
	inDim := objectDim(domain)
	outDim := objectDim(codomain)

	if outDim < inDim {
		return nil, fmt.Errorf("inject: codomain dim %d < domain dim %d", outDim, inDim)
	}

	// Embed input into top-left corner of larger matrix
	result := NewMatrix(outDim, outDim)
	for i := 0; i < inDim && i < input.Rows; i++ {
		for j := 0; j < inDim && j < input.Cols; j++ {
			result.Set(i, j, input.Get(i, j))
		}
	}
	return result, nil
}

// applyProject applies projection from a biproduct: A⊕B → A.
// The output is the top-left block of the input matrix, truncated
// to the codomain dimension.
func (e *Executor) applyProject(domain, codomain Object, input *Matrix) (*Matrix, error) {
	outDim := objectDim(codomain)

	if outDim > input.Rows || outDim > input.Cols {
		return nil, fmt.Errorf("project: codomain dim %d > input dim %dx%d", outDim, input.Rows, input.Cols)
	}

	// Extract top-left block
	result := NewMatrix(outDim, outDim)
	for i := 0; i < outDim; i++ {
		for j := 0; j < outDim; j++ {
			result.Set(i, j, input.Get(i, j))
		}
	}
	return result, nil
}

// applyCopy applies classical copying: C(k) → C(k)⊗C(k).
// For a classical system of dimension k, this maps a diagonal density
// matrix diag(p_0, ..., p_{k-1}) to the k²×k² diagonal matrix
// diag(p_0, 0, ..., 0, p_1, 0, ..., 0, p_{k-1}).
// Specifically, the output has non-zero entries only at positions
// (i*k+i, i*k+i) = p_i, implementing |i⟩ → |i,i⟩.
func (e *Executor) applyCopy(domain Object, input *Matrix) (*Matrix, error) {
	k := input.Rows
	outDim := k * k

	result := NewMatrix(outDim, outDim)
	for i := 0; i < k; i++ {
		// |i⟩ maps to |i,i⟩ which has index i*k + i
		idx := i*k + i
		result.Set(idx, idx, input.Get(i, i))
	}
	return result, nil
}

// applyDelete applies classical deletion: C(k) → I.
// Returns the trace of the input as a 1x1 matrix. For a classical
// (diagonal) density matrix, this sums the probabilities.
func (e *Executor) applyDelete(input *Matrix) (*Matrix, error) {
	tr := Trace(input)
	result := NewMatrix(1, 1)
	result.Set(0, 0, tr)
	return result, nil
}

// applyEncode applies classical-to-quantum encoding: C(k) → Q(k).
// A diagonal classical density matrix is already a valid quantum density
// matrix, so this returns the input unchanged.
func (e *Executor) applyEncode(domain Object, input *Matrix) (*Matrix, error) {
	return input.Clone(), nil
}

// applyDecode applies quantum-to-classical decoding: Q(k) → C(k).
// Measures in the computational basis by extracting the diagonal of the
// density matrix, producing a diagonal (classical) density matrix.
func (e *Executor) applyDecode(domain Object, input *Matrix) (*Matrix, error) {
	n := input.Rows
	result := NewMatrix(n, n)
	for i := 0; i < n; i++ {
		result.Set(i, i, input.Get(i, i))
	}
	return result, nil
}

// applyTrace applies the quantum trace: Q(n) → I.
// Returns Tr(ρ) as a 1x1 matrix.
func (e *Executor) applyTrace(input *Matrix) (*Matrix, error) {
	tr := Trace(input)
	result := NewMatrix(1, 1)
	result.Set(0, 0, tr)
	return result, nil
}

// applyKraus applies a Kraus representation: Φ(ρ) = Σ_k K_k ρ K_k†.
// The Kraus operators are stored in the circuit's Data field as a
// Tag("kraus", Seq(matrix_1, matrix_2, ...)).
func (e *Executor) applyKraus(c Circuit, input *Matrix) (*Matrix, error) {
	tag, ok := c.Data.(Tag)
	if !ok {
		return nil, fmt.Errorf("kraus: data must be a Tag")
	}
	label, ok := tag.Label.(Text)
	if !ok || label.V != "kraus" {
		return nil, fmt.Errorf("kraus: data must be Tag(\"kraus\", ...)")
	}
	seq, ok := tag.Payload.(Seq)
	if !ok {
		return nil, fmt.Errorf("kraus: payload must be a Seq of matrices")
	}

	if len(seq.Items) == 0 {
		outDim := objectDim(c.Codomain)
		return NewMatrix(outDim, outDim), nil
	}

	var result *Matrix
	for i, item := range seq.Items {
		K, ok := MatrixFromValue(item)
		if !ok {
			return nil, fmt.Errorf("kraus: operator %d is not a valid matrix", i)
		}
		// Compute K ρ K†
		Kdag := Dagger(K)
		term := MatMul(MatMul(K, input), Kdag)
		if term == nil {
			return nil, fmt.Errorf("kraus: dimension mismatch for operator %d", i)
		}
		if result == nil {
			result = term
		} else {
			result = MatAdd(result, term)
			if result == nil {
				return nil, fmt.Errorf("kraus: dimension mismatch in sum at operator %d", i)
			}
		}
	}
	return result, nil
}

// applyUnitary applies a unitary operation: U ρ U†.
func (e *Executor) applyUnitary(c Circuit, input *Matrix) (*Matrix, error) {
	// Get unitary matrix from data
	U, ok := MatrixFromValue(c.Data)
	if !ok {
		return nil, fmt.Errorf("unitary data must be matrix")
	}
	// Compute U ρ U†
	Udag := Dagger(U)
	return MatMul(MatMul(U, input), Udag), nil
}

// applyChoi applies a channel via its Choi matrix.
// The Choi matrix J of a channel Φ: Q(n_in) → Q(n_out) is a
// (n_in * n_out) × (n_in * n_out) matrix. The channel is reconstructed as:
//   Φ(ρ) = Tr_in[(ρ^T ⊗ I_out) J]
// where the partial trace is over the input subsystem.
func (e *Executor) applyChoi(c Circuit, input *Matrix) (*Matrix, error) {
	// Get Choi matrix from data
	J, ok := MatrixFromValue(c.Data)
	if !ok {
		return nil, fmt.Errorf("choi data must be matrix")
	}

	// Use Hilbert space dimensions (block sizes), not density matrix dimensions.
	inDim := BlockDim(c.Domain)
	outDim := BlockDim(c.Codomain)

	// Apply Choi-Jamiolkowski isomorphism
	// Φ(ρ) = Tr_in[(ρ^T ⊗ I_out) J]
	result := NewMatrix(outDim, outDim)

	for i := 0; i < outDim; i++ {
		for j := 0; j < outDim; j++ {
			sum := QIZero()
			for k := 0; k < inDim; k++ {
				for l := 0; l < inDim; l++ {
					// ρ^T[k,l] * J[k*outDim+i, l*outDim+j]
					rhoEntry := input.Get(l, k) // Transpose
					jRow := k*outDim + i
					jCol := l*outDim + j
					if jRow < J.Rows && jCol < J.Cols {
						jEntry := J.Get(jRow, jCol)
						sum = QIAdd(sum, QIMul(rhoEntry, jEntry))
					}
				}
			}
			result.Set(i, j, sum)
		}
	}

	return result, nil
}

// applyPrepare prepares a fixed state.
func (e *Executor) applyPrepare(c Circuit) (*Matrix, error) {
	// Get prepared state from data
	rho, ok := MatrixFromValue(c.Data)
	if !ok {
		return nil, fmt.Errorf("prepare data must be matrix")
	}
	return rho.Clone(), nil
}

// objectDim computes the dimension of an object.
func objectDim(obj Object) int {
	if len(obj.Blocks) == 0 {
		return 1
	}
	dim := 0
	for _, n := range obj.Blocks {
		dim += int(n * n)
	}
	return dim
}

// BlockDim computes the Hilbert space dimension (sum of block sizes).
func BlockDim(obj Object) int {
	if len(obj.Blocks) == 0 {
		return 1
	}
	dim := 0
	for _, n := range obj.Blocks {
		dim += int(n)
	}
	return dim
}

// CircuitToValue converts a circuit to a Value.
func CircuitToValue(c Circuit) Value {
	children := make([]Value, len(c.Children))
	for i, id := range c.Children {
		children[i] = MakeBytes(id[:])
	}

	data := c.Data
	if data == nil {
		data = MakeNil()
	}

	return MakeTag(
		MakeText("circuit"),
		MakeSeq(
			ObjectToValue(c.Domain),
			ObjectToValue(c.Codomain),
			MakeInt(int64(c.Prim)),
			data,
			MakeSeq(children...),
		),
	)
}

// CircuitFromValue parses a circuit from a Value.
func CircuitFromValue(v Value) (Circuit, bool) {
	tag, ok := v.(Tag)
	if !ok {
		return Circuit{}, false
	}
	label, ok := tag.Label.(Text)
	if !ok || label.V != "circuit" {
		return Circuit{}, false
	}
	seq, ok := tag.Payload.(Seq)
	if !ok || len(seq.Items) < 5 {
		return Circuit{}, false
	}

	domain, ok := ObjectFromValue(seq.Items[0])
	if !ok {
		return Circuit{}, false
	}
	codomain, ok := ObjectFromValue(seq.Items[1])
	if !ok {
		return Circuit{}, false
	}
	prim, ok := seq.Items[2].(Int)
	if !ok {
		return Circuit{}, false
	}
	data := seq.Items[3]
	childSeq, ok := seq.Items[4].(Seq)
	if !ok {
		return Circuit{}, false
	}

	children := make([][32]byte, len(childSeq.Items))
	for i, item := range childSeq.Items {
		bytes, ok := item.(Bytes)
		if !ok || len(bytes.V) < 32 {
			return Circuit{}, false
		}
		copy(children[i][:], bytes.V[:32])
	}

	return Circuit{
		Domain:   domain,
		Codomain: codomain,
		Prim:     Prim(prim.V.Int64()),
		Data:     data,
		Children: children,
	}, true
}

// ObjectToValue converts an object to a Value.
func ObjectToValue(obj Object) Value {
	blocks := make([]Value, len(obj.Blocks))
	for i, n := range obj.Blocks {
		blocks[i] = MakeInt(int64(n))
	}
	return MakeTag(
		MakeText("object"),
		MakeSeq(blocks...),
	)
}

// ObjectFromValue parses an object from a Value.
func ObjectFromValue(v Value) (Object, bool) {
	tag, ok := v.(Tag)
	if !ok {
		return Object{}, false
	}
	label, ok := tag.Label.(Text)
	if !ok || label.V != "object" {
		return Object{}, false
	}
	seq, ok := tag.Payload.(Seq)
	if !ok {
		return Object{}, false
	}

	blocks := make([]uint32, len(seq.Items))
	for i, item := range seq.Items {
		n, ok := item.(Int)
		if !ok {
			return Object{}, false
		}
		blocks[i] = uint32(n.V.Int64())
	}
	return Object{Blocks: blocks}, true
}

// ObjectEqual checks if two objects are equal.
func ObjectEqual(a, b Object) bool {
	if len(a.Blocks) != len(b.Blocks) {
		return false
	}
	for i := range a.Blocks {
		if a.Blocks[i] != b.Blocks[i] {
			return false
		}
	}
	return true
}
