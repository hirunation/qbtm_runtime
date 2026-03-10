// Package qkd provides quantum key distribution protocol implementations.
package qkd

import (
	"math/big"

	"qbtm/runtime"
)

// Gate constants for QKD protocols.
// All gates are represented as matrices over Q(i) (Gaussian rationals).
// For irrational entries like 1/sqrt(2), we use high-precision rational approximations.

// Rational approximation of 1/sqrt(2) with high precision.
// 1/sqrt(2) ~ 7071067811865475244/10000000000000000000
// For practical purposes we use a simpler approximation that preserves unitarity approximately.
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

// CNOT returns the controlled-NOT gate as a 4x4 matrix.
// CNOT = [[1,0,0,0], [0,1,0,0], [0,0,0,1], [0,0,1,0]]
// Control on first qubit, target on second.
func CNOT() *runtime.Matrix {
	cnot := runtime.NewMatrix(4, 4)
	one := runtime.QIOne()
	cnot.Set(0, 0, one)
	cnot.Set(1, 1, one)
	cnot.Set(2, 3, one)
	cnot.Set(3, 2, one)
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

// Phase returns the S gate (phase gate).
// S = [[1, 0], [0, i]]
func Phase() *runtime.Matrix {
	s := runtime.NewMatrix(2, 2)
	one := runtime.QIOne()
	i := runtime.QII()
	s.Set(0, 0, one)
	s.Set(1, 1, i)
	return s
}

// PhaseDagger returns the S-dagger gate.
// S^dag = [[1, 0], [0, -i]]
func PhaseDagger() *runtime.Matrix {
	s := runtime.NewMatrix(2, 2)
	one := runtime.QIOne()
	negI := runtime.QINeg(runtime.QII())
	s.Set(0, 0, one)
	s.Set(1, 1, negI)
	return s
}

// TGate returns the T gate (pi/8 gate).
// T = [[1, 0], [0, e^(i*pi/4)]]
// Using rational approximation: e^(i*pi/4) = (1+i)/sqrt(2)
func TGate() *runtime.Matrix {
	t := runtime.NewMatrix(2, 2)
	one := runtime.QIOne()
	// e^(i*pi/4) ~ (1/sqrt(2)) + (1/sqrt(2))*i
	expIPi4 := runtime.QI{
		Re: new(big.Rat).Set(Sqrt2Inv),
		Im: new(big.Rat).Set(Sqrt2Inv),
	}
	t.Set(0, 0, one)
	t.Set(1, 1, expIPi4)
	return t
}

// TDagger returns the T-dagger gate.
// T^dag = [[1, 0], [0, e^(-i*pi/4)]]
func TDagger() *runtime.Matrix {
	t := runtime.NewMatrix(2, 2)
	one := runtime.QIOne()
	// e^(-i*pi/4) ~ (1/sqrt(2)) - (1/sqrt(2))*i
	expNegIPi4 := runtime.QI{
		Re: new(big.Rat).Set(Sqrt2Inv),
		Im: new(big.Rat).Neg(Sqrt2Inv),
	}
	t.Set(0, 0, one)
	t.Set(1, 1, expNegIPi4)
	return t
}

// SWAP returns the SWAP gate as a 4x4 matrix.
// SWAP = [[1,0,0,0], [0,0,1,0], [0,1,0,0], [0,0,0,1]]
func SWAP() *runtime.Matrix {
	swap := runtime.NewMatrix(4, 4)
	one := runtime.QIOne()
	swap.Set(0, 0, one)
	swap.Set(1, 2, one)
	swap.Set(2, 1, one)
	swap.Set(3, 3, one)
	return swap
}

// Standard quantum states as column vectors.

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

// KetPlusI returns the |+i> state: (|0> + i|1>)/sqrt(2) (Y-basis).
func KetPlusI() *runtime.Matrix {
	ket := runtime.NewMatrix(2, 1)
	s := runtime.QI{Re: new(big.Rat).Set(Sqrt2Inv), Im: new(big.Rat)}
	iS := runtime.QI{Re: new(big.Rat), Im: new(big.Rat).Set(Sqrt2Inv)}
	ket.Set(0, 0, s)
	ket.Set(1, 0, iS)
	return ket
}

// KetMinusI returns the |-i> state: (|0> - i|1>)/sqrt(2) (Y-basis).
func KetMinusI() *runtime.Matrix {
	ket := runtime.NewMatrix(2, 1)
	s := runtime.QI{Re: new(big.Rat).Set(Sqrt2Inv), Im: new(big.Rat)}
	negIS := runtime.QI{Re: new(big.Rat), Im: new(big.Rat).Neg(Sqrt2Inv)}
	ket.Set(0, 0, s)
	ket.Set(1, 0, negIS)
	return ket
}

// Bell states

// BellPhiPlus returns the Bell state |Phi+> = (|00> + |11>)/sqrt(2).
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

// Density matrices

// DensityMatrix computes |psi><psi| from a ket vector.
func DensityMatrix(ket *runtime.Matrix) *runtime.Matrix {
	return runtime.OuterProduct(ket, ket)
}

// Rho0 returns the density matrix |0><0|.
func Rho0() *runtime.Matrix {
	return DensityMatrix(Ket0())
}

// Rho1 returns the density matrix |1><1|.
func Rho1() *runtime.Matrix {
	return DensityMatrix(Ket1())
}

// RhoPlus returns the density matrix |+><+|.
func RhoPlus() *runtime.Matrix {
	return DensityMatrix(KetPlus())
}

// RhoMinus returns the density matrix |-><-|.
func RhoMinus() *runtime.Matrix {
	return DensityMatrix(KetMinus())
}

// RhoPlusI returns the density matrix |+i><+i|.
func RhoPlusI() *runtime.Matrix {
	return DensityMatrix(KetPlusI())
}

// RhoMinusI returns the density matrix |-i><-i|.
func RhoMinusI() *runtime.Matrix {
	return DensityMatrix(KetMinusI())
}

// RhoBellPhiPlus returns the density matrix |Phi+><Phi+|.
func RhoBellPhiPlus() *runtime.Matrix {
	return DensityMatrix(BellPhiPlus())
}

// MaximallyMixed returns the maximally mixed state I/d for dimension d.
func MaximallyMixed(d int) *runtime.Matrix {
	rho := runtime.Identity(d)
	scale := big.NewRat(1, int64(d))
	return runtime.MatScale(rho, scale)
}

// Measurement projectors

// ZBasisProjectors returns the Z-basis measurement projectors {|0><0|, |1><1|}.
func ZBasisProjectors() []*runtime.Matrix {
	return []*runtime.Matrix{Rho0(), Rho1()}
}

// XBasisProjectors returns the X-basis measurement projectors {|+><+|, |-><-|}.
func XBasisProjectors() []*runtime.Matrix {
	return []*runtime.Matrix{RhoPlus(), RhoMinus()}
}

// YBasisProjectors returns the Y-basis measurement projectors {|+i><+i|, |-i><-i|}.
func YBasisProjectors() []*runtime.Matrix {
	return []*runtime.Matrix{RhoPlusI(), RhoMinusI()}
}

// Helper functions for protocol synthesis

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

// Symbolic representation for exact gates

// SymbolicSqrt2Inv returns a tagged value representing 1/sqrt(2) symbolically.
func SymbolicSqrt2Inv() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("symbolic"),
		runtime.MakeSeq(
			runtime.MakeText("sqrt2-inv"),
			runtime.MakeBigRat(Sqrt2Inv), // rational approximation for computation
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

// BasisIndex represents which basis to use.
type BasisIndex int

const (
	BasisZ BasisIndex = iota // Computational basis: |0>, |1>
	BasisX                   // Hadamard basis: |+>, |->
	BasisY                   // Y basis: |+i>, |-i>
)

// GetBasisStates returns the two states for a given basis.
func GetBasisStates(basis BasisIndex) (*runtime.Matrix, *runtime.Matrix) {
	switch basis {
	case BasisZ:
		return Ket0(), Ket1()
	case BasisX:
		return KetPlus(), KetMinus()
	case BasisY:
		return KetPlusI(), KetMinusI()
	default:
		return Ket0(), Ket1()
	}
}

// GetBasisProjectors returns measurement projectors for a given basis.
func GetBasisProjectors(basis BasisIndex) []*runtime.Matrix {
	switch basis {
	case BasisZ:
		return ZBasisProjectors()
	case BasisX:
		return XBasisProjectors()
	case BasisY:
		return YBasisProjectors()
	default:
		return ZBasisProjectors()
	}
}
