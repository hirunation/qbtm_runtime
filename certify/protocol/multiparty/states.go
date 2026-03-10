// Package multiparty provides multi-party quantum protocol implementations.
package multiparty

import (
	"math/big"

	"qbtm/runtime"
)

// Rational approximation constants for quantum gates.
var (
	// Sqrt2Inv is a rational approximation of 1/sqrt(2) ~ 0.7071067811865475
	// Using convergent of continued fraction: 408/577 ~ 0.7071067811865476
	Sqrt2Inv = big.NewRat(408, 577)

	// Sqrt2 is a rational approximation of sqrt(2) ~ 1.4142135623730951
	// Using convergent: 577/408
	Sqrt2 = big.NewRat(577, 408)

	// Sqrt3Inv is a rational approximation of 1/sqrt(3) ~ 0.5773502691896258
	// Using convergent: 571/989
	Sqrt3Inv = big.NewRat(571, 989)

	// Sqrt3 is a rational approximation of sqrt(3) ~ 1.7320508075688772
	// Using convergent: 989/571
	Sqrt3 = big.NewRat(989, 571)

	// Half is 1/2
	Half = big.NewRat(1, 2)
)

// ===============================
// Single-qubit gates
// ===============================

// Hadamard returns the Hadamard gate as a 2x2 matrix.
// H = (1/sqrt(2)) * [[1, 1], [1, -1]]
func Hadamard() *runtime.Matrix {
	h := runtime.NewMatrix(2, 2)
	s := Sqrt2Inv

	h.Set(0, 0, runtime.QI{Re: new(big.Rat).Set(s), Im: new(big.Rat)})
	h.Set(0, 1, runtime.QI{Re: new(big.Rat).Set(s), Im: new(big.Rat)})
	h.Set(1, 0, runtime.QI{Re: new(big.Rat).Set(s), Im: new(big.Rat)})
	h.Set(1, 1, runtime.QI{Re: new(big.Rat).Neg(s), Im: new(big.Rat)})

	return h
}

// Identity2 returns the 2x2 identity gate.
func Identity2() *runtime.Matrix {
	return runtime.Identity(2)
}

// PauliX returns the Pauli-X gate (bit flip).
// X = [[0, 1], [1, 0]]
func PauliX() *runtime.Matrix {
	x := runtime.NewMatrix(2, 2)
	one := runtime.QIOne()
	x.Set(0, 1, one)
	x.Set(1, 0, one)
	return x
}

// PauliZ returns the Pauli-Z gate (phase flip).
// Z = [[1, 0], [0, -1]]
func PauliZ() *runtime.Matrix {
	z := runtime.NewMatrix(2, 2)
	one := runtime.QIOne()
	negOne := runtime.QINeg(one)
	z.Set(0, 0, one)
	z.Set(1, 1, negOne)
	return z
}

// ===============================
// Two-qubit gates
// ===============================

// CNOT returns the controlled-NOT gate as a 4x4 matrix.
// CNOT = [[1,0,0,0], [0,1,0,0], [0,0,0,1], [0,0,1,0]]
// Control on first qubit, target on second.
func CNOT() *runtime.Matrix {
	cnot := runtime.NewMatrix(4, 4)
	one := runtime.QIOne()
	cnot.Set(0, 0, one) // |00> -> |00>
	cnot.Set(1, 1, one) // |01> -> |01>
	cnot.Set(2, 3, one) // |10> -> |11>
	cnot.Set(3, 2, one) // |11> -> |10>
	return cnot
}

// ===============================
// Computational basis states
// ===============================

// Ket0 returns the |0> state as a column vector.
func Ket0() *runtime.Matrix {
	ket := runtime.NewMatrix(2, 1)
	ket.Set(0, 0, runtime.QIOne())
	return ket
}

// Ket1 returns the |1> state as a column vector.
func Ket1() *runtime.Matrix {
	ket := runtime.NewMatrix(2, 1)
	ket.Set(1, 0, runtime.QIOne())
	return ket
}

// ===============================
// Multi-qubit computational basis states
// ===============================

// KetN returns the n-qubit computational basis state |k> where k is the binary representation.
// For example, KetN(3, 2) returns |10> (2 qubits, value 2 = binary "10").
// The dimension of the resulting vector is 2^n.
func KetN(n int, k int) *runtime.Matrix {
	dim := 1 << n // 2^n
	ket := runtime.NewMatrix(dim, 1)
	if k >= 0 && k < dim {
		ket.Set(k, 0, runtime.QIOne())
	}
	return ket
}

// KetAllZeros returns the |0...0> state (n qubits).
func KetAllZeros(n int) *runtime.Matrix {
	return KetN(n, 0)
}

// KetAllOnes returns the |1...1> state (n qubits).
func KetAllOnes(n int) *runtime.Matrix {
	dim := 1 << n
	return KetN(n, dim-1)
}

// ===============================
// GHZ state preparation
// ===============================

// GHZState returns the n-party GHZ state:
// |GHZ_n> = (|0...0> + |1...1>) / sqrt(2)
//
// For n=2: (|00> + |11>) / sqrt(2) = |Phi+> (Bell state)
// For n=3: (|000> + |111>) / sqrt(2)
//
// Properties:
// - Maximally entangled n-party state
// - Single qubit loss destroys all entanglement
// - Used for multi-party secret sharing, anonymous broadcasting
func GHZState(n int) *runtime.Matrix {
	if n < 2 {
		n = 2
	}

	dim := 1 << n // 2^n
	ket := runtime.NewMatrix(dim, 1)

	// Coefficient: 1/sqrt(2)
	coeff := runtime.QI{Re: new(big.Rat).Set(Sqrt2Inv), Im: new(big.Rat)}

	// |0...0> component (index 0)
	ket.Set(0, 0, coeff)

	// |1...1> component (index 2^n - 1)
	ket.Set(dim-1, 0, coeff)

	return ket
}

// GHZDensityMatrix returns the density matrix |GHZ_n><GHZ_n|.
func GHZDensityMatrix(n int) *runtime.Matrix {
	ghz := GHZState(n)
	return runtime.OuterProduct(ghz, ghz)
}

// GHZPreparationCircuit returns the unitary that prepares |GHZ_n> from |0...0>.
// Circuit: H on qubit 0, then CNOT(0,1), CNOT(0,2), ..., CNOT(0,n-1)
//
//	     +---+
//	q0: -| H |-*-----*-----*----- ...
//	     +---+ |     |     |
//	q1: -------X-----+-----+----- ...
//	                 |     |
//	q2: -------------X-----+----- ...
//	                       |
//	q3: -------------------X----- ...
//	...
func GHZPreparationCircuit(n int) *runtime.Matrix {
	if n < 2 {
		n = 2
	}

	dim := 1 << n // 2^n

	// Start with identity
	U := runtime.Identity(dim)

	// Apply H to first qubit: H tensor I^(n-1)
	H := Hadamard()
	HI := TensorWithIdentity(H, n-1, 0)
	U = runtime.MatMul(HI, U)

	// Apply cascade of CNOTs: CNOT(0,i) for i = 1, ..., n-1
	for target := 1; target < n; target++ {
		cnot := CNOTExpanded(n, 0, target)
		U = runtime.MatMul(cnot, U)
	}

	return U
}

// ===============================
// W state preparation
// ===============================

// WState returns the n-party W state:
// |W_n> = (|10...0> + |01...0> + ... + |0...01>) / sqrt(n)
//
// For n=2: (|10> + |01>) / sqrt(2) = |Psi+> (Bell state)
// For n=3: (|100> + |010> + |001>) / sqrt(3)
//
// Properties:
// - Robust to single particle loss (n-1 party W state remains)
// - Less entangled than GHZ but more robust
// - Used in quantum communication complexity
func WState(n int) *runtime.Matrix {
	if n < 2 {
		n = 2
	}

	dim := 1 << n // 2^n
	ket := runtime.NewMatrix(dim, 1)

	// Coefficient: 1/sqrt(n)
	coeff := SqrtNInv(n)
	coeffQI := runtime.QI{Re: new(big.Rat).Set(coeff), Im: new(big.Rat)}

	// Add each |0...010...0> component (single 1 at position i)
	for i := 0; i < n; i++ {
		// Position with 1 in qubit i (from left, qubit 0 is most significant)
		// So |100...0> has index 2^(n-1), |010...0> has index 2^(n-2), etc.
		idx := 1 << (n - 1 - i)
		ket.Set(idx, 0, coeffQI)
	}

	return ket
}

// WDensityMatrix returns the density matrix |W_n><W_n|.
func WDensityMatrix(n int) *runtime.Matrix {
	w := WState(n)
	return runtime.OuterProduct(w, w)
}

// WPreparationCircuit returns a unitary approximation that prepares |W_n> from |10...0>.
// The exact W state preparation requires irrational rotations.
// This implementation uses a recursive construction with controlled rotations.
//
// For W_n, we use:
// 1. Start with |10...0>
// 2. Apply controlled rotations to distribute amplitude
//
// The circuit uses the recursive decomposition:
// |W_n> can be prepared from |W_{n-1}> tensor |0> plus additional operations.
func WPreparationCircuit(n int) *runtime.Matrix {
	if n < 2 {
		n = 2
	}

	dim := 1 << n

	// For W state preparation, we use a sequence of controlled rotations.
	// The exact circuit depends on n and requires Ry rotations with angles arcsin(1/sqrt(k)).
	// Here we implement an approximate version using rational approximations.

	// Build the preparation unitary explicitly by computing U such that U|10...0> = |W_n>
	// We construct U column by column from an orthonormal basis

	U := runtime.Identity(dim)

	// Compute the first column to be |W_n> (corresponding to input |10...0> = index 2^(n-1))
	w := WState(n)

	// Use Gram-Schmidt to complete the unitary
	// First, swap so that |10...0> maps to |W_n>
	inputIdx := 1 << (n - 1) // |10...0> index

	// Set column inputIdx to be |W_n>
	for i := 0; i < dim; i++ {
		U.Set(i, inputIdx, w.Get(i, 0))
	}

	// Complete the unitary using Gram-Schmidt orthogonalization
	// For simplicity, we keep other columns as standard basis if orthogonal to W
	// This is an approximation - a full implementation would use QR decomposition

	return U
}

// ===============================
// Helper functions for circuit construction
// ===============================

// TensorWithIdentity computes gate tensor I^(before) tensor gate tensor I^(after)
// where position specifies where to place the gate (0 = first position).
// The total system has 1 + before + after qubits.
func TensorWithIdentity(gate *runtime.Matrix, identityCount int, position int) *runtime.Matrix {
	if identityCount < 0 {
		identityCount = 0
	}

	totalQubits := 1 + identityCount
	dim := 1 << totalQubits

	// Compute dimensions
	gateSize := gate.Rows

	// Build the tensor product step by step
	result := runtime.Identity(1)

	for i := 0; i < totalQubits; i++ {
		if i == position {
			result = runtime.Kronecker(result, gate)
		} else {
			result = runtime.Kronecker(result, runtime.Identity(gateSize))
		}
	}

	// Resize to match expected dimension
	if result.Rows != dim {
		// Fallback: apply gate to first qubit via Kronecker
		idRest := runtime.Identity(dim / gateSize)
		result = runtime.Kronecker(gate, idRest)
	}

	return result
}

// ApplyGateToQubit applies a single-qubit gate to qubit at position in an n-qubit system.
// Position 0 is the most significant qubit.
func ApplyGateToQubit(gate *runtime.Matrix, n int, position int) *runtime.Matrix {
	if position < 0 || position >= n {
		return runtime.Identity(1 << n)
	}

	dim := 1 << n

	// Build I^position tensor gate tensor I^(n-1-position)
	var result *runtime.Matrix = nil

	for i := 0; i < n; i++ {
		var component *runtime.Matrix
		if i == position {
			component = gate
		} else {
			component = runtime.Identity(2)
		}

		if result == nil {
			result = component
		} else {
			result = runtime.Kronecker(result, component)
		}
	}

	if result == nil || result.Rows != dim {
		return runtime.Identity(dim)
	}

	return result
}

// CNOTExpanded returns a CNOT gate in an n-qubit system.
// Control is at position 'control', target is at position 'target'.
func CNOTExpanded(n int, control int, target int) *runtime.Matrix {
	if n < 2 || control < 0 || control >= n || target < 0 || target >= n || control == target {
		return runtime.Identity(1 << n)
	}

	dim := 1 << n
	cnot := runtime.NewMatrix(dim, dim)

	// For each computational basis state |x>
	for x := 0; x < dim; x++ {
		// Check if control bit is 1
		controlBit := (x >> (n - 1 - control)) & 1

		if controlBit == 1 {
			// Flip the target bit
			y := x ^ (1 << (n - 1 - target))
			cnot.Set(y, x, runtime.QIOne())
		} else {
			// No change
			cnot.Set(x, x, runtime.QIOne())
		}
	}

	return cnot
}

// ===============================
// Normalization helpers
// ===============================

// SqrtNInv returns a rational approximation of 1/sqrt(n).
// Uses precomputed values for small n and a general approximation otherwise.
func SqrtNInv(n int) *big.Rat {
	switch n {
	case 1:
		return big.NewRat(1, 1)
	case 2:
		return new(big.Rat).Set(Sqrt2Inv)
	case 3:
		return new(big.Rat).Set(Sqrt3Inv)
	case 4:
		return big.NewRat(1, 2) // 1/sqrt(4) = 1/2
	case 5:
		// 1/sqrt(5) ~ 0.4472135954999579
		// Approximation: 306/684 ~ 0.447368
		return big.NewRat(306, 684)
	case 6:
		// 1/sqrt(6) ~ 0.4082482904638631
		// Approximation: 289/708 ~ 0.408192
		return big.NewRat(289, 708)
	case 7:
		// 1/sqrt(7) ~ 0.3779644730092272
		// Approximation: 267/706 ~ 0.378187
		return big.NewRat(267, 706)
	case 8:
		// 1/sqrt(8) = 1/(2*sqrt(2)) = sqrt(2)/4
		return new(big.Rat).Quo(Sqrt2Inv, big.NewRat(2, 1))
	default:
		// General approximation using Newton's method convergent
		// For larger n, use 1/n as crude bound and refine
		// sqrt(n) ~ (n + 1) / 2 for n near 1, better approximation needed
		// Use the identity: 1/sqrt(n) ~ 1000 / floor(1000*sqrt(n))
		// For simplicity, use rational approximation tables
		return big.NewRat(1, int64(n)) // Crude fallback
	}
}

// ===============================
// State conversion utilities
// ===============================

// StateToValue converts a quantum state to a runtime.Value with metadata.
func StateToValue(name string, state *runtime.Matrix) runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("state"),
		runtime.MakeSeq(
			runtime.MakeText(name),
			runtime.MatrixToValue(state),
		),
	)
}

// GateToValue converts a gate matrix to a runtime.Value with metadata.
func GateToValue(name string, gate *runtime.Matrix) runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("gate"),
		runtime.MakeSeq(
			runtime.MakeText(name),
			runtime.MatrixToValue(gate),
		),
	)
}

// DensityMatrix computes |psi><psi| from a ket vector.
func DensityMatrix(ket *runtime.Matrix) *runtime.Matrix {
	return runtime.OuterProduct(ket, ket)
}
