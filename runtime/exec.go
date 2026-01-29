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
		// Swap acts by permutation
		return e.applySwap(c.Domain, c.Codomain, input)

	case PrimDiscard:
		// Discard traces out the system
		return e.applyDiscard(c.Domain, input)

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

	default:
		return nil, fmt.Errorf("unsupported primitive: %v", c.Prim)
	}
}

// applySwap applies a swap operation.
func (e *Executor) applySwap(domain, codomain Object, input *Matrix) (*Matrix, error) {
	// Simple implementation: compute swap matrix and apply
	n := objectDim(domain)
	result := NewMatrix(n, n)
	// Simplified: just return identity for now
	for i := 0; i < n; i++ {
		result.Set(i, i, QIOne())
	}
	return MatMul(MatMul(result, input), Dagger(result)), nil
}

// applyDiscard applies a discard operation (partial trace).
func (e *Executor) applyDiscard(domain Object, input *Matrix) (*Matrix, error) {
	// Return trace as a 1x1 matrix (scalar)
	tr := Trace(input)
	result := NewMatrix(1, 1)
	result.Set(0, 0, tr)
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
func (e *Executor) applyChoi(c Circuit, input *Matrix) (*Matrix, error) {
	// Get Choi matrix from data
	J, ok := MatrixFromValue(c.Data)
	if !ok {
		return nil, fmt.Errorf("choi data must be matrix")
	}

	inDim := objectDim(c.Domain)
	outDim := objectDim(c.Codomain)

	// Apply Choi-Jamiolkowski isomorphism
	// Φ(ρ) = Tr_in[(ρ^T ⊗ I) J]
	result := NewMatrix(outDim, outDim)

	// Simplified implementation
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
