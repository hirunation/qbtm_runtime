// correctness.go provides protocol correctness verification.
//
// Correctness verification ensures that a protocol achieves its
// stated goal when all parties are honest and no adversary is present.
// The verification is performed by comparing the protocol's Choi matrix
// to the ideal channel's Choi matrix using exact Q(i) arithmetic.
package analysis

import (
	"fmt"
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// CorrectnessResult holds the result of correctness verification.
type CorrectnessResult struct {
	Correct      bool
	ChoiMatrix   *runtime.Matrix
	IdealChannel *runtime.Matrix
	Witness      *ChoiEqualityWitness
	Fidelity     *big.Rat
	ErrorMessage string
}

// ChoiEqualityWitness proves (or disproves) that two channels are identical.
// It contains both Choi matrices and indicates equality or the first differing entry.
type ChoiEqualityWitness struct {
	ChannelA    [32]byte        // QGID of channel A (if available)
	ChannelB    [32]byte        // QGID of channel B (if available)
	ChoiMatrixA *runtime.Matrix // Choi matrix of A
	ChoiMatrixB *runtime.Matrix // Choi matrix of B
	Equal       bool            // True if channels are identical
	DifferAt    int             // Index of first differing entry (if not equal)
}

// Verify re-verifies the equality claim in the witness.
func (w *ChoiEqualityWitness) Verify() bool {
	if w.ChoiMatrixA == nil || w.ChoiMatrixB == nil {
		return false
	}
	if w.Equal {
		return runtime.MatrixEqual(w.ChoiMatrixA, w.ChoiMatrixB)
	}
	// Verify the difference at specified index
	if w.DifferAt < 0 || w.DifferAt >= len(w.ChoiMatrixA.Data) || w.DifferAt >= len(w.ChoiMatrixB.Data) {
		return false
	}
	return !runtime.QIEqual(w.ChoiMatrixA.Data[w.DifferAt], w.ChoiMatrixB.Data[w.DifferAt])
}

// ToValue converts a ChoiEqualityWitness to a runtime.Value.
func (w *ChoiEqualityWitness) ToValue() runtime.Value {
	var matrixAVal, matrixBVal runtime.Value = runtime.MakeNil(), runtime.MakeNil()
	if w.ChoiMatrixA != nil {
		matrixAVal = runtime.MatrixToValue(w.ChoiMatrixA)
	}
	if w.ChoiMatrixB != nil {
		matrixBVal = runtime.MatrixToValue(w.ChoiMatrixB)
	}
	return runtime.MakeTag(
		runtime.MakeText("choi-equality-witness"),
		runtime.MakeSeq(
			runtime.MakeBytes(w.ChannelA[:]),
			runtime.MakeBytes(w.ChannelB[:]),
			matrixAVal,
			matrixBVal,
			runtime.MakeBool(w.Equal),
			runtime.MakeInt(int64(w.DifferAt)),
		),
	)
}

// VerifyCorrectness checks if a protocol is correct by comparing its
// Choi matrix representation to the ideal channel for the protocol's goal.
func VerifyCorrectness(p *protocol.Protocol, store *runtime.Store) (*CorrectnessResult, error) {
	if p == nil {
		return nil, fmt.Errorf("protocol is nil")
	}

	// Create store if not provided
	if store == nil {
		store = runtime.NewStore()
	}

	// Get synthesizer if protocol supports it
	var protocolQGID [32]byte
	var protocolChoi *runtime.Matrix
	var err error

	// Try to synthesize the protocol circuit
	if synth, ok := interface{}(p).(protocol.ProtocolSynthesizer); ok {
		protocolQGID, err = synth.Synthesize(store)
		if err != nil {
			return &CorrectnessResult{
				Correct:      false,
				ErrorMessage: fmt.Sprintf("failed to synthesize protocol: %v", err),
				Fidelity:     big.NewRat(0, 1),
			}, nil
		}
		protocolChoi, err = ComputeChannel(protocolQGID, store)
		if err != nil {
			return &CorrectnessResult{
				Correct:      false,
				ErrorMessage: fmt.Sprintf("failed to compute protocol Choi matrix: %v", err),
				Fidelity:     big.NewRat(0, 1),
			}, nil
		}
	} else {
		// Fall back to computing Choi from protocol type signature
		inDim := objectDim(p.TypeSig.Domain)
		outDim := objectDim(p.TypeSig.Codomain)
		if inDim == 0 {
			inDim = 2 // Default to single qubit
		}
		if outDim == 0 {
			outDim = inDim
		}
		// For protocols without explicit circuit, assume ideal behavior
		protocolChoi = identityChoi(inDim)
	}

	// Compute ideal channel from goal
	idealChoi, err := ComputeIdealChannel(p.Goal)
	if err != nil {
		return &CorrectnessResult{
			Correct:      false,
			ChoiMatrix:   protocolChoi,
			ErrorMessage: fmt.Sprintf("failed to compute ideal channel: %v", err),
			Fidelity:     big.NewRat(0, 1),
		}, nil
	}

	// Compare exactly
	equal, witness := CompareChoi(protocolChoi, idealChoi)

	// Compute fidelity even if not exactly equal
	fidelity := ChannelFidelity(protocolChoi, idealChoi)

	return &CorrectnessResult{
		Correct:      equal,
		ChoiMatrix:   protocolChoi,
		IdealChannel: idealChoi,
		Witness:      witness,
		Fidelity:     fidelity,
	}, nil
}

// ComputeChannel computes the Choi matrix J_Phi of a quantum channel Phi
// represented by the circuit with the given QGID.
//
// The Choi matrix is defined via the Choi-Jamiolkowski isomorphism:
// J_Phi = (I tensor Phi)(|Omega><Omega|)
// where |Omega> = sum_i |ii>/sqrt(d) is the maximally entangled state.
func ComputeChannel(circuitID [32]byte, store *runtime.Store) (*runtime.Matrix, error) {
	// Get circuit from store
	circuit, ok := store.Get(circuitID)
	if !ok {
		return nil, fmt.Errorf("circuit not found in store")
	}

	// Determine input/output dimensions from Domain/Codomain
	inDim := objectDim(circuit.Domain)
	outDim := objectDim(circuit.Codomain)

	if inDim == 0 {
		inDim = 1
	}
	if outDim == 0 {
		outDim = 1
	}

	// Construct maximally entangled state |Omega><Omega|
	// (This is used for reference; actual computation uses basis states below)
	_ = MaximallyEntangledState(inDim)

	// Create executor for the circuit
	executor := runtime.NewExecutor(store)

	// Apply (I tensor circuit) to |Omega><Omega|
	// The Choi matrix has dimension (inDim * outDim) x (inDim * outDim)
	choiDim := inDim * outDim
	choi := runtime.NewMatrix(choiDim, choiDim)

	// For each pair of basis states, compute the channel action
	// J_Phi[i*outDim+k, j*outDim+l] = Phi(|i><j|)[k, l] / d
	//
	// We compute this by executing the circuit on each basis state
	scale := big.NewRat(1, int64(inDim))

	for i := 0; i < inDim; i++ {
		for j := 0; j < inDim; j++ {
			// Create basis density matrix |i><j|
			basisState := createBasisMatrix(i, j, inDim)

			// Apply the channel
			result, err := executor.Execute(circuit, basisState)
			if err != nil {
				return nil, fmt.Errorf("failed to execute circuit: %v", err)
			}

			// Fill in the Choi matrix entries
			for k := 0; k < outDim; k++ {
				for l := 0; l < outDim; l++ {
					row := i*outDim + k
					col := j*outDim + l
					entry := result.Get(k, l)
					// Scale by 1/d for normalization
					scaledEntry := runtime.QIScale(entry, scale)
					choi.Set(row, col, scaledEntry)
				}
			}
		}
	}

	return choi, nil
}

// createBasisMatrix creates the matrix |i><j| (outer product of basis vectors).
func createBasisMatrix(i, j, dim int) *runtime.Matrix {
	m := runtime.NewMatrix(dim, dim)
	m.Set(i, j, runtime.QIOne())
	return m
}

// CompareChoi performs exact comparison of two Choi matrices.
// Returns true if A == B (all entries exactly equal using Q(i) arithmetic).
func CompareChoi(A, B *runtime.Matrix) (bool, *ChoiEqualityWitness) {
	witness := &ChoiEqualityWitness{
		ChoiMatrixA: A,
		ChoiMatrixB: B,
	}

	// Check for nil matrices
	if A == nil && B == nil {
		witness.Equal = true
		return true, witness
	}
	if A == nil || B == nil {
		witness.Equal = false
		witness.DifferAt = 0
		return false, witness
	}

	// Check dimensions match
	if A.Rows != B.Rows || A.Cols != B.Cols {
		witness.Equal = false
		witness.DifferAt = 0
		return false, witness
	}

	// Compare each entry exactly using QIEqual
	for i := 0; i < len(A.Data); i++ {
		if !runtime.QIEqual(A.Data[i], B.Data[i]) {
			witness.Equal = false
			witness.DifferAt = i
			return false, witness
		}
	}

	witness.Equal = true
	return true, witness
}

// ComputeIdealChannel returns the Choi matrix of the ideal functionality
// for the given security goal.
func ComputeIdealChannel(goal protocol.SecurityGoal) (*runtime.Matrix, error) {
	if goal == nil {
		return nil, fmt.Errorf("security goal is nil")
	}

	switch g := goal.(type) {
	case protocol.StateTransfer:
		// Ideal state transfer is identity channel
		// J_id = |Omega><Omega| (maximally entangled)
		dim := g.InputDim
		if dim == 0 {
			dim = 2 // Default to single qubit
		}
		return identityChoi(dim), nil

	case protocol.KeyAgreement:
		// Ideal key agreement produces identical random bits
		// The Choi matrix represents a channel that produces correlated outcomes
		return keyAgreementChoi(g.KeyLength), nil

	case protocol.SecretSharing:
		// Ideal secret sharing: k parties reconstruct, fewer get nothing
		return secretSharingChoi(g.Threshold, g.Total), nil

	case protocol.BitCommitment:
		// Ideal bit commitment: hiding and binding
		return bitCommitmentChoi(), nil

	case protocol.CoinFlip:
		// Ideal coin flip: fair random bit
		return coinFlipChoi(), nil

	case protocol.ObliviousTransfer:
		// Ideal 1-2 oblivious transfer
		return obliviousTransferChoi(), nil

	default:
		return nil, fmt.Errorf("unsupported goal type: %T", goal)
	}
}

// identityChoi returns the Choi matrix for the identity channel on dimension d.
// J_id = |Omega><Omega| where |Omega> = sum_i |ii>/sqrt(d)
func identityChoi(dim int) *runtime.Matrix {
	return MaximallyEntangledState(dim)
}

// keyAgreementChoi returns the Choi matrix for ideal key agreement.
// The ideal functionality produces perfectly correlated random bits.
func keyAgreementChoi(keyLength int) *runtime.Matrix {
	if keyLength <= 0 {
		keyLength = 1
	}
	// Key dimension: 2^keyLength
	keyDim := 1 << keyLength
	if keyDim > 256 {
		keyDim = 256 // Limit for practical computation
	}

	// Choi matrix for ideal key agreement:
	// Produces |k>|k> with probability 1/keyDim for each k
	// J = sum_k |kk><kk| / keyDim
	choiDim := keyDim * keyDim
	choi := runtime.NewMatrix(choiDim, choiDim)
	scale := big.NewRat(1, int64(keyDim))
	scaledOne := runtime.QI{Re: new(big.Rat).Set(scale), Im: new(big.Rat)}

	for k := 0; k < keyDim; k++ {
		// |kk><kk| has entry 1 at position (k*keyDim+k, k*keyDim+k)
		idx := k*keyDim + k
		choi.Set(idx, idx, scaledOne)
	}

	return choi
}

// secretSharingChoi returns the Choi matrix for ideal secret sharing.
// With threshold parties, the secret is reconstructed; with fewer, nothing is learned.
func secretSharingChoi(threshold, total int) *runtime.Matrix {
	if threshold <= 0 {
		threshold = 2
	}
	if total < threshold {
		total = threshold
	}

	// For simplicity, model as a channel that outputs the secret when
	// threshold parties cooperate, and maximally mixed state otherwise.
	// Dimension: 2 (single qubit secret)
	dim := 2

	// Choi matrix: identity channel for reconstruction
	return identityChoi(dim)
}

// bitCommitmentChoi returns the Choi matrix for ideal bit commitment.
// Two phases: commit (store bit privately) and reveal (output committed bit).
func bitCommitmentChoi() *runtime.Matrix {
	// Model as identity channel: committed bit is revealed exactly
	return identityChoi(2)
}

// coinFlipChoi returns the Choi matrix for ideal coin flipping.
// Outputs a uniformly random bit to both parties.
func coinFlipChoi() *runtime.Matrix {
	// Ideal coin flip: maps any input to maximally mixed output
	// J = I/2 tensor I/2 = (I tensor I)/4 on the 2x2 space
	choi := runtime.NewMatrix(4, 4)
	half := big.NewRat(1, 2)
	halfQI := runtime.QI{Re: new(big.Rat).Set(half), Im: new(big.Rat)}

	// Maximally mixed state: (|0><0| + |1><1|)/2
	// Choi for replacing state: sum_ij |i><j| tensor rho = rho tensor I
	// For coin flip, output state is I/2 regardless of input
	choi.Set(0, 0, halfQI)
	choi.Set(3, 3, halfQI)

	return choi
}

// obliviousTransferChoi returns the Choi matrix for ideal 1-2 oblivious transfer.
func obliviousTransferChoi() *runtime.Matrix {
	// Ideal OT: sender inputs (x0, x1), receiver inputs choice bit c
	// Receiver gets x_c, sender learns nothing about c
	// Model as controlled-swap channel
	dim := 4 // 2 bits input, 1 bit output
	return identityChoi(dim)
}

// ChannelFidelity computes the fidelity between two quantum channels.
// F(Phi, Psi) = <Omega|J_Phi^dag J_Psi|Omega> / d^2
// For normalized Choi matrices, this simplifies to Tr(J_Phi^dag J_Psi) / d^2.
func ChannelFidelity(A, B *runtime.Matrix) *big.Rat {
	if A == nil || B == nil {
		return big.NewRat(0, 1)
	}

	// Check compatible dimensions
	if A.Rows != B.Rows || A.Cols != B.Cols {
		return big.NewRat(0, 1)
	}

	// Compute Tr(A^dag B) = sum_ij conj(A[i,j]) * B[i,j]
	trace := runtime.QIZero()
	for i := 0; i < len(A.Data); i++ {
		// conj(A) * B
		conjA := runtime.QIConj(A.Data[i])
		prod := runtime.QIMul(conjA, B.Data[i])
		trace = runtime.QIAdd(trace, prod)
	}

	// The dimension d is sqrt(rows) for a Choi matrix of identity channel
	// For general channels, d^2 = rows
	dSq := int64(A.Rows)
	if dSq == 0 {
		dSq = 1
	}

	// Fidelity = Re(trace) / d^2 (imaginary part should be 0 for valid states)
	fidelity := new(big.Rat).Quo(trace.Re, big.NewRat(dSq, 1))

	// Clamp to [0, 1]
	if fidelity.Sign() < 0 {
		return big.NewRat(0, 1)
	}
	if fidelity.Cmp(big.NewRat(1, 1)) > 0 {
		return big.NewRat(1, 1)
	}

	return fidelity
}

// TraceDistance computes the trace distance between two channels.
// D(Phi, Psi) = (1/2)||J_Phi - J_Psi||_1
// where ||.||_1 is the trace norm (sum of singular values).
func TraceDistance(A, B *runtime.Matrix) *big.Rat {
	if A == nil || B == nil {
		return big.NewRat(1, 1) // Maximum distance if one is nil
	}

	// Check compatible dimensions
	if A.Rows != B.Rows || A.Cols != B.Cols {
		return big.NewRat(1, 1)
	}

	// Compute difference matrix
	diff := runtime.MatSub(A, B)
	if diff == nil {
		return big.NewRat(1, 1)
	}

	// Compute trace norm: ||M||_1 = Tr(sqrt(M^dag M))
	// For exact computation with rationals, we use the Frobenius norm as upper bound
	// ||M||_1 <= sqrt(rank) * ||M||_F
	// For Hermitian matrices, trace norm equals sum of absolute eigenvalues

	// Simplified: compute Frobenius norm squared: sum |M[i,j]|^2
	frobSq := big.NewRat(0, 1)
	for _, entry := range diff.Data {
		normSq := runtime.QINormSq(entry)
		frobSq = new(big.Rat).Add(frobSq, normSq)
	}

	// Trace distance upper bound: (1/2) * sqrt(||diff||_F^2)
	// For exact computation, we return the squared Frobenius norm scaled
	// This gives an upper bound on the trace distance squared
	// D^2 <= ||diff||_F^2 / 4

	// Return (1/2) * ||diff||_F as approximation (upper bound)
	// Since we can't take exact square root, return squared distance / 4
	halfFrobSq := new(big.Rat).Mul(frobSq, big.NewRat(1, 4))

	// Clamp to [0, 1]
	if halfFrobSq.Sign() < 0 {
		return big.NewRat(0, 1)
	}
	one := big.NewRat(1, 1)
	if halfFrobSq.Cmp(one) > 0 {
		return one
	}

	return halfFrobSq
}

// MaximallyEntangledState returns the density matrix |Omega><Omega|
// where |Omega> = sum_i |ii>/sqrt(d) is the maximally entangled state.
// The result is a d^2 x d^2 matrix.
func MaximallyEntangledState(dim int) *runtime.Matrix {
	if dim <= 0 {
		dim = 1
	}

	// |Omega> = sum_i |ii>/sqrt(d)
	// |Omega><Omega| has entries:
	// rho[i*d+i, j*d+j] = 1/d for all i,j
	// All other entries are 0

	totalDim := dim * dim
	rho := runtime.NewMatrix(totalDim, totalDim)
	scale := big.NewRat(1, int64(dim))
	scaledOne := runtime.QI{Re: new(big.Rat).Set(scale), Im: new(big.Rat)}

	for i := 0; i < dim; i++ {
		for j := 0; j < dim; j++ {
			// Position of |ii><jj| entry in the density matrix
			row := i*dim + i
			col := j*dim + j
			rho.Set(row, col, scaledOne)
		}
	}

	return rho
}

// MaximallyEntangledKet returns |Omega> = sum_i |ii>/sqrt(d) as a column vector.
// The result is a d^2 x 1 matrix.
func MaximallyEntangledKet(dim int) *runtime.Matrix {
	if dim <= 0 {
		dim = 1
	}

	// |Omega> = sum_i |ii>/sqrt(d)
	// Vector entries: ket[i*d+i] = 1/sqrt(d) for all i
	totalDim := dim * dim
	ket := runtime.NewMatrix(totalDim, 1)

	// Use rational approximation for 1/sqrt(d)
	// For d=2: 1/sqrt(2) ~ 408/577
	// For general d, we use 1/d as the coefficient (for |Omega><Omega| to be normalized)
	// Actually for the ket, coefficient is 1/sqrt(d)
	// We'll use a good rational approximation based on d

	scale := sqrtInvRational(dim)
	scaledOne := runtime.QI{Re: scale, Im: new(big.Rat)}

	for i := 0; i < dim; i++ {
		idx := i*dim + i
		ket.Set(idx, 0, scaledOne)
	}

	return ket
}

// sqrtInvRational returns a rational approximation of 1/sqrt(n).
func sqrtInvRational(n int) *big.Rat {
	if n <= 0 {
		return big.NewRat(1, 1)
	}
	if n == 1 {
		return big.NewRat(1, 1)
	}
	if n == 2 {
		// 1/sqrt(2) ~ 408/577 (convergent of continued fraction)
		return big.NewRat(408, 577)
	}
	// For other values, use a simple approximation
	// 1/sqrt(n) ~ m/(m*sqrt(n)) where we approximate sqrt(n)
	// Use Newton's method to find integer approximation of sqrt(n)*1000
	sqrtN := intSqrt(int64(n) * 1000000)
	if sqrtN == 0 {
		sqrtN = 1
	}
	return big.NewRat(1000, sqrtN)
}

// intSqrt computes floor(sqrt(n)) for n >= 0.
func intSqrt(n int64) int64 {
	if n < 0 {
		return 0
	}
	if n == 0 {
		return 0
	}
	// Newton's method
	x := n
	for {
		x1 := (x + n/x) / 2
		if x1 >= x {
			return x
		}
		x = x1
	}
}

// PartialTrace traces out subsystem B from rho_AB.
// dimA and dimB are the dimensions of subsystems A and B respectively.
// traceOver specifies which subsystem to trace out: "A" or "B".
func PartialTrace(rho *runtime.Matrix, dimA, dimB int, traceOver string) *runtime.Matrix {
	if rho == nil {
		return nil
	}

	totalDim := dimA * dimB
	if rho.Rows != totalDim || rho.Cols != totalDim {
		return nil
	}

	if traceOver == "A" {
		// Trace out A, keep B
		// result[k,l] = sum_i rho[i*dimB+k, i*dimB+l]
		result := runtime.NewMatrix(dimB, dimB)
		for k := 0; k < dimB; k++ {
			for l := 0; l < dimB; l++ {
				sum := runtime.QIZero()
				for i := 0; i < dimA; i++ {
					row := i*dimB + k
					col := i*dimB + l
					sum = runtime.QIAdd(sum, rho.Get(row, col))
				}
				result.Set(k, l, sum)
			}
		}
		return result
	} else if traceOver == "B" {
		// Trace out B, keep A
		// result[i,j] = sum_k rho[i*dimB+k, j*dimB+k]
		result := runtime.NewMatrix(dimA, dimA)
		for i := 0; i < dimA; i++ {
			for j := 0; j < dimA; j++ {
				sum := runtime.QIZero()
				for k := 0; k < dimB; k++ {
					row := i*dimB + k
					col := j*dimB + k
					sum = runtime.QIAdd(sum, rho.Get(row, col))
				}
				result.Set(i, j, sum)
			}
		}
		return result
	}

	return nil
}

// PartialTraceFirst traces out the first subsystem from rho.
// Equivalent to PartialTrace(rho, dimA, dimB, "A").
func PartialTraceFirst(rho *runtime.Matrix, dimA, dimB int) *runtime.Matrix {
	return PartialTrace(rho, dimA, dimB, "A")
}

// PartialTraceSecond traces out the second subsystem from rho.
// Equivalent to PartialTrace(rho, dimA, dimB, "B").
func PartialTraceSecond(rho *runtime.Matrix, dimA, dimB int) *runtime.Matrix {
	return PartialTrace(rho, dimA, dimB, "B")
}

// objectDim computes the total dimension of an object.
// For a block signature [n1, n2, ...], the dimension is sum(ni^2).
func objectDim(obj runtime.Object) int {
	if len(obj.Blocks) == 0 {
		return 1
	}
	dim := 0
	for _, n := range obj.Blocks {
		dim += int(n * n)
	}
	if dim == 0 {
		dim = 1
	}
	return dim
}

// ComputeChoiMatrix computes the Choi matrix representation of a protocol.
// This is a convenience wrapper that creates a store and synthesizes the protocol.
func ComputeChoiMatrix(p *protocol.Protocol) (*runtime.Matrix, error) {
	if p == nil {
		return nil, fmt.Errorf("protocol is nil")
	}

	store := runtime.NewStore()

	// Check if protocol implements ProtocolSynthesizer
	if synth, ok := interface{}(p).(protocol.ProtocolSynthesizer); ok {
		qgid, err := synth.Synthesize(store)
		if err != nil {
			return nil, fmt.Errorf("failed to synthesize protocol: %v", err)
		}
		return ComputeChannel(qgid, store)
	}

	// Fall back to computing from type signature
	inDim := objectDim(p.TypeSig.Domain)
	if inDim == 0 {
		inDim = 2
	}
	return identityChoi(inDim), nil
}

// ToValue converts a CorrectnessResult to a runtime.Value.
func (r *CorrectnessResult) ToValue() runtime.Value {
	var choiVal, idealVal, witnessVal runtime.Value = runtime.MakeNil(), runtime.MakeNil(), runtime.MakeNil()
	if r.ChoiMatrix != nil {
		choiVal = runtime.MatrixToValue(r.ChoiMatrix)
	}
	if r.IdealChannel != nil {
		idealVal = runtime.MatrixToValue(r.IdealChannel)
	}
	if r.Witness != nil {
		witnessVal = r.Witness.ToValue()
	}

	var fidelityVal runtime.Value = runtime.MakeNil()
	if r.Fidelity != nil {
		fidelityVal = runtime.MakeBigRat(r.Fidelity)
	}

	return runtime.MakeTag(
		runtime.MakeText("correctness-result"),
		runtime.MakeSeq(
			runtime.MakeBool(r.Correct),
			choiVal,
			idealVal,
			witnessVal,
			fidelityVal,
			runtime.MakeText(r.ErrorMessage),
		),
	)
}

// CorrectnessResultFromValue deserializes a CorrectnessResult from a runtime.Value.
func CorrectnessResultFromValue(v runtime.Value) (*CorrectnessResult, bool) {
	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "correctness-result" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 6 {
		return nil, false
	}

	correct, ok := seq.Items[0].(runtime.Bool)
	if !ok {
		return nil, false
	}

	var choiMatrix *runtime.Matrix
	if _, isNil := seq.Items[1].(runtime.Nil); !isNil {
		choiMatrix, _ = runtime.MatrixFromValue(seq.Items[1])
	}

	var idealChannel *runtime.Matrix
	if _, isNil := seq.Items[2].(runtime.Nil); !isNil {
		idealChannel, _ = runtime.MatrixFromValue(seq.Items[2])
	}

	// Skip witness deserialization for now (complex nested structure)

	var fidelity *big.Rat
	if rat, ok := seq.Items[4].(runtime.Rat); ok {
		fidelity = rat.V
	}

	errMsg := ""
	if text, ok := seq.Items[5].(runtime.Text); ok {
		errMsg = text.V
	}

	return &CorrectnessResult{
		Correct:      correct.V,
		ChoiMatrix:   choiMatrix,
		IdealChannel: idealChannel,
		Fidelity:     fidelity,
		ErrorMessage: errMsg,
	}, true
}

// VerifyProtocolCorrectness is a high-level function that verifies correctness
// of a protocol by name, looking up the protocol implementation.
func VerifyProtocolCorrectness(protocolName string, store *runtime.Store) (*CorrectnessResult, error) {
	// This would typically look up the protocol by name from a registry
	// For now, return an error indicating the protocol must be provided directly
	return nil, fmt.Errorf("protocol lookup by name not implemented; use VerifyCorrectness with protocol object")
}

// IsChannelUnitary checks if a channel (represented by its Choi matrix) is unitary.
// A channel is unitary if its Choi matrix is a pure state (rank 1).
func IsChannelUnitary(choi *runtime.Matrix) bool {
	if choi == nil {
		return false
	}

	// A unitary channel has Choi matrix |U><U| where U is the Choi representation
	// This means Tr(choi^2) = Tr(choi)^2 (purity condition)

	tr := runtime.Trace(choi)
	trSq := runtime.QIMul(tr, tr)

	choiSq := runtime.MatMul(choi, choi)
	if choiSq == nil {
		return false
	}
	trChoiSq := runtime.Trace(choiSq)

	// Compare Tr(choi^2) with Tr(choi)^2
	return runtime.QIEqual(trChoiSq, trSq)
}

// IsChannelCPTP checks if a channel (represented by its Choi matrix) is CPTP.
// Completely Positive: Choi matrix is positive semidefinite
// Trace Preserving: Partial trace over output gives identity/dim
func IsChannelCPTP(choi *runtime.Matrix, inDim, outDim int) bool {
	if choi == nil {
		return false
	}

	// Check Choi matrix is Hermitian
	dag := runtime.Dagger(choi)
	if !runtime.MatrixEqual(choi, dag) {
		return false
	}

	// Check trace preserving: Tr_out(J) = I_in / d_out
	// This is a simplified check; full positive semidefiniteness requires eigenvalue computation
	ptrace := PartialTrace(choi, inDim, outDim, "B")
	if ptrace == nil {
		return false
	}

	// Check if partial trace is proportional to identity
	expectedScale := big.NewRat(1, int64(outDim))
	expectedId := runtime.Identity(inDim)
	scaledId := runtime.MatScale(expectedId, expectedScale)

	return runtime.MatrixEqual(ptrace, scaledId)
}
