// Package communication provides quantum communication protocol implementations.
package communication

import (
	"math/big"

	"qbtm/runtime"
)

// Rational approximation constants for quantum gates.
// These are shared across all communication protocols.
var (
	// Sqrt2Inv is a rational approximation of 1/sqrt(2) ~ 0.7071067811865475
	// Using convergent of continued fraction: 408/577 ~ 0.7071067811865476
	Sqrt2Inv = big.NewRat(408, 577)

	// Sqrt2 is a rational approximation of sqrt(2) ~ 1.4142135623730951
	// Using convergent: 577/408
	Sqrt2 = big.NewRat(577, 408)

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

	// H[0,0] = 1/sqrt(2)
	h.Set(0, 0, runtime.QI{Re: new(big.Rat).Set(s), Im: new(big.Rat)})
	// H[0,1] = 1/sqrt(2)
	h.Set(0, 1, runtime.QI{Re: new(big.Rat).Set(s), Im: new(big.Rat)})
	// H[1,0] = 1/sqrt(2)
	h.Set(1, 0, runtime.QI{Re: new(big.Rat).Set(s), Im: new(big.Rat)})
	// H[1,1] = -1/sqrt(2)
	h.Set(1, 1, runtime.QI{Re: new(big.Rat).Neg(s), Im: new(big.Rat)})

	return h
}

// Identity2 returns the 2x2 identity gate.
// I = [[1, 0], [0, 1]]
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

// PauliY returns the Pauli-Y gate.
// Y = [[0, -i], [i, 0]]
func PauliY() *runtime.Matrix {
	y := runtime.NewMatrix(2, 2)
	i := runtime.QII()
	negI := runtime.QINeg(i)
	y.Set(0, 1, negI)
	y.Set(1, 0, i)
	return y
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

// CZ returns the controlled-Z gate as a 4x4 matrix.
// CZ = [[1,0,0,0], [0,1,0,0], [0,0,1,0], [0,0,0,-1]]
func CZ() *runtime.Matrix {
	cz := runtime.NewMatrix(4, 4)
	one := runtime.QIOne()
	negOne := runtime.QINeg(one)
	cz.Set(0, 0, one)
	cz.Set(1, 1, one)
	cz.Set(2, 2, one)
	cz.Set(3, 3, negOne)
	return cz
}

// SWAP returns the SWAP gate as a 4x4 matrix.
// SWAP = [[1,0,0,0], [0,0,1,0], [0,1,0,0], [0,0,0,1]]
func SWAP() *runtime.Matrix {
	swap := runtime.NewMatrix(4, 4)
	one := runtime.QIOne()
	swap.Set(0, 0, one) // |00> -> |00>
	swap.Set(1, 2, one) // |01> -> |10>
	swap.Set(2, 1, one) // |10> -> |01>
	swap.Set(3, 3, one) // |11> -> |11>
	return swap
}

// ===============================
// Standard quantum states
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

// KetPlus returns the |+> state: (|0> + |1>)/sqrt(2).
func KetPlus() *runtime.Matrix {
	ket := runtime.NewMatrix(2, 1)
	s := runtime.QI{Re: new(big.Rat).Set(Sqrt2Inv), Im: new(big.Rat)}
	ket.Set(0, 0, s)
	ket.Set(1, 0, s)
	return ket
}

// KetMinus returns the |-> state: (|0> - |1>)/sqrt(2).
func KetMinus() *runtime.Matrix {
	ket := runtime.NewMatrix(2, 1)
	s := runtime.QI{Re: new(big.Rat).Set(Sqrt2Inv), Im: new(big.Rat)}
	negS := runtime.QINeg(s)
	ket.Set(0, 0, s)
	ket.Set(1, 0, negS)
	return ket
}

// ===============================
// Bell states
// ===============================

// BellPhiPlus returns the Bell state |Phi+> = (|00> + |11>)/sqrt(2).
// This is the maximally entangled state used in teleportation and superdense coding.
func BellPhiPlus() *runtime.Matrix {
	ket := runtime.NewMatrix(4, 1)
	s := runtime.QI{Re: new(big.Rat).Set(Sqrt2Inv), Im: new(big.Rat)}
	ket.Set(0, 0, s) // |00>
	ket.Set(3, 0, s) // |11>
	return ket
}

// BellPhiMinus returns the Bell state |Phi-> = (|00> - |11>)/sqrt(2).
func BellPhiMinus() *runtime.Matrix {
	ket := runtime.NewMatrix(4, 1)
	s := runtime.QI{Re: new(big.Rat).Set(Sqrt2Inv), Im: new(big.Rat)}
	negS := runtime.QINeg(s)
	ket.Set(0, 0, s)    // |00>
	ket.Set(3, 0, negS) // -|11>
	return ket
}

// BellPsiPlus returns the Bell state |Psi+> = (|01> + |10>)/sqrt(2).
func BellPsiPlus() *runtime.Matrix {
	ket := runtime.NewMatrix(4, 1)
	s := runtime.QI{Re: new(big.Rat).Set(Sqrt2Inv), Im: new(big.Rat)}
	ket.Set(1, 0, s) // |01>
	ket.Set(2, 0, s) // |10>
	return ket
}

// BellPsiMinus returns the Bell state |Psi-> = (|01> - |10>)/sqrt(2).
func BellPsiMinus() *runtime.Matrix {
	ket := runtime.NewMatrix(4, 1)
	s := runtime.QI{Re: new(big.Rat).Set(Sqrt2Inv), Im: new(big.Rat)}
	negS := runtime.QINeg(s)
	ket.Set(1, 0, s)    // |01>
	ket.Set(2, 0, negS) // -|10>
	return ket
}

// BellState returns the i-th Bell state (0-indexed).
// 0: |Phi+>, 1: |Phi->, 2: |Psi+>, 3: |Psi->
func BellState(index int) *runtime.Matrix {
	switch index {
	case 0:
		return BellPhiPlus()
	case 1:
		return BellPhiMinus()
	case 2:
		return BellPsiPlus()
	case 3:
		return BellPsiMinus()
	default:
		return BellPhiPlus()
	}
}

// ===============================
// Density matrices
// ===============================

// DensityMatrix computes |psi><psi| from a ket vector.
func DensityMatrix(ket *runtime.Matrix) *runtime.Matrix {
	return runtime.OuterProduct(ket, ket)
}

// RhoBellPhiPlus returns the density matrix |Phi+><Phi+|.
func RhoBellPhiPlus() *runtime.Matrix {
	return DensityMatrix(BellPhiPlus())
}

// RhoBellPhiMinus returns the density matrix |Phi-><Phi-|.
func RhoBellPhiMinus() *runtime.Matrix {
	return DensityMatrix(BellPhiMinus())
}

// RhoBellPsiPlus returns the density matrix |Psi+><Psi+|.
func RhoBellPsiPlus() *runtime.Matrix {
	return DensityMatrix(BellPsiPlus())
}

// RhoBellPsiMinus returns the density matrix |Psi-><Psi-|.
func RhoBellPsiMinus() *runtime.Matrix {
	return DensityMatrix(BellPsiMinus())
}

// ===============================
// Bell measurement operators
// ===============================

// BellMeasurementProjectors returns the four Bell state projectors for Bell measurement.
// These are used in teleportation (Alice's measurement) and superdense coding (Bob's measurement).
// Returns: [|Phi+><Phi+|, |Phi-><Phi-|, |Psi+><Psi+|, |Psi-><Psi-|]
func BellMeasurementProjectors() [4]*runtime.Matrix {
	return [4]*runtime.Matrix{
		RhoBellPhiPlus(),
		RhoBellPhiMinus(),
		RhoBellPsiPlus(),
		RhoBellPsiMinus(),
	}
}

// BellMeasurementUnitary returns the unitary that transforms computational basis
// to Bell basis: U|ij> = |Bell_{ij}>
// This is CNOT followed by H on first qubit.
func BellMeasurementUnitary() *runtime.Matrix {
	// Bell measurement circuit: CNOT then H tensor I
	// First apply CNOT, then Hadamard on first qubit
	cnot := CNOT()
	h := Hadamard()

	// H tensor I (Hadamard on first qubit, identity on second)
	hI := runtime.NewMatrix(4, 4)
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			hij := h.Get(i, j)
			for k := 0; k < 2; k++ {
				// (H tensor I)[2*i+k, 2*j+k] = H[i,j] * I[k,k] = H[i,j] if k matches
				hI.Set(2*i+k, 2*j+k, hij)
			}
		}
	}

	// Compose: (H tensor I) * CNOT
	return runtime.MatMul(hI, cnot)
}

// ===============================
// Correction operators for teleportation
// ===============================

// CorrectionOperator returns the correction operator for teleportation.
// Based on Bell measurement outcome (m1, m2):
//   - 00 -> I (identity)
//   - 01 -> X (bit flip)
//   - 10 -> Z (phase flip)
//   - 11 -> XZ (both)
func CorrectionOperator(m1, m2 int) *runtime.Matrix {
	if m1 == 0 && m2 == 0 {
		return Identity2()
	} else if m1 == 0 && m2 == 1 {
		return PauliX()
	} else if m1 == 1 && m2 == 0 {
		return PauliZ()
	} else { // m1 == 1 && m2 == 1
		// XZ = X * Z
		return runtime.MatMul(PauliX(), PauliZ())
	}
}

// AllCorrectionOperators returns all four correction operators.
// Index i corresponds to measurement outcome i (0=00, 1=01, 2=10, 3=11).
func AllCorrectionOperators() [4]*runtime.Matrix {
	return [4]*runtime.Matrix{
		CorrectionOperator(0, 0), // I
		CorrectionOperator(0, 1), // X
		CorrectionOperator(1, 0), // Z
		CorrectionOperator(1, 1), // XZ
	}
}

// ===============================
// Bell state preparation circuit
// ===============================

// BellPreparationCircuit returns the unitary that prepares |Phi+> from |00>.
// Circuit: H on first qubit, then CNOT.
// H|0> = |+>, then CNOT(|+>|0>) = (|00> + |11>)/sqrt(2) = |Phi+>
func BellPreparationCircuit() *runtime.Matrix {
	// First apply H tensor I
	h := Hadamard()
	hI := runtime.NewMatrix(4, 4)
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			hij := h.Get(i, j)
			for k := 0; k < 2; k++ {
				hI.Set(2*i+k, 2*j+k, hij)
			}
		}
	}

	// Then apply CNOT
	cnot := CNOT()

	// Compose: CNOT * (H tensor I)
	return runtime.MatMul(cnot, hI)
}

// ===============================
// Encoding operators for superdense coding
// ===============================

// SuperdenseEncodingOperator returns the encoding operator for superdense coding.
// Alice encodes 2 classical bits (b1, b2) by applying this to her half of the Bell pair:
//   - 00 -> I (identity)
//   - 01 -> X (bit flip)
//   - 10 -> Z (phase flip)
//   - 11 -> XZ (both) = iY
func SuperdenseEncodingOperator(b1, b2 int) *runtime.Matrix {
	// Same as correction operators but applied before sending
	return CorrectionOperator(b1, b2)
}

// AllSuperdenseEncodings returns all four encoding operators.
func AllSuperdenseEncodings() [4]*runtime.Matrix {
	return AllCorrectionOperators()
}

// ===============================
// Helper functions
// ===============================

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

// MakeQIReal creates a QI with only real part.
func MakeQIReal(r *big.Rat) runtime.QI {
	return runtime.QI{Re: new(big.Rat).Set(r), Im: new(big.Rat)}
}

// MakeQIImag creates a QI with only imaginary part.
func MakeQIImag(r *big.Rat) runtime.QI {
	return runtime.QI{Re: new(big.Rat), Im: new(big.Rat).Set(r)}
}

// MakeQI creates a QI from two rationals.
func MakeQI(re, im *big.Rat) runtime.QI {
	return runtime.NewQI(re, im)
}
