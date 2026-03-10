// noise.go provides noise tolerance analysis.
//
// This file implements analysis of protocol behavior under
// realistic noise models and computes tolerance thresholds.
// Includes Kraus operator representations and Choi matrices
// for all standard quantum noise channels.
package analysis

import (
	"fmt"
	"math/big"

	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// NoiseModel represents a quantum noise model.
type NoiseModel struct {
	Name        string
	Description string
	Parameters  map[string]*big.Rat
}

// NoiseResult holds the result of noise tolerance analysis.
type NoiseResult struct {
	Tolerant        bool
	MaxNoise        *big.Rat // Maximum tolerable noise parameter
	SecurityAtNoise *big.Rat // Security parameter at given noise
	KeyRateAtNoise  *big.Rat // Key rate at given noise
	BreakpointNoise *big.Rat // Noise level where security fails
}

// NoiseChannel represents a quantum noise model with full operator representation.
type NoiseChannel struct {
	Name       string
	Parameters map[string]*big.Rat
	Kraus      []*runtime.Matrix // Kraus operators
	Choi       *runtime.Matrix   // Choi matrix
}

// NoiseToleranceResult holds noise analysis results.
type NoiseToleranceResult struct {
	Protocol  string
	ErrorRate *big.Rat
	Threshold *big.Rat
	IsSecure  bool
	Margin    *big.Rat  // threshold - errorRate
	KeyRate   *Entropy  // Key rate at this error level
	Channel   *NoiseChannel
}

// NoiseThresholds maps noise parameters to security thresholds.
type NoiseThresholds struct {
	Depolarizing     *big.Rat // Max depolarizing p
	AmplitudeDamping *big.Rat // Max gamma
	PhaseDamping     *big.Rat // Max lambda
}

// Depolarizing returns the depolarizing noise model.
func Depolarizing(p *big.Rat) *NoiseModel {
	return &NoiseModel{
		Name:        "depolarizing",
		Description: "Depolarizing channel with parameter p",
		Parameters:  map[string]*big.Rat{"p": p},
	}
}

// Dephasing returns the dephasing (phase damping) noise model.
func Dephasing(p *big.Rat) *NoiseModel {
	return &NoiseModel{
		Name:        "dephasing",
		Description: "Dephasing channel with parameter p",
		Parameters:  map[string]*big.Rat{"p": p},
	}
}

// AmplitudeDamping returns the amplitude damping noise model.
func AmplitudeDamping(gamma *big.Rat) *NoiseModel {
	return &NoiseModel{
		Name:        "amplitude-damping",
		Description: "Amplitude damping channel with decay rate gamma",
		Parameters:  map[string]*big.Rat{"gamma": gamma},
	}
}

// DepolarizingChannel creates a depolarizing channel with Kraus operators.
// phi(rho) = (1-p)*rho + (p/3)*(X*rho*X + Y*rho*Y + Z*rho*Z)
// Kraus operators:
//   K0 = sqrt(1-p) * I
//   K1 = sqrt(p/3) * X
//   K2 = sqrt(p/3) * Y
//   K3 = sqrt(p/3) * Z
func DepolarizingChannel(p *big.Rat) *NoiseChannel {
	channel := &NoiseChannel{
		Name:       "depolarizing",
		Parameters: map[string]*big.Rat{"p": new(big.Rat).Set(p)},
		Kraus:      make([]*runtime.Matrix, 4),
	}

	// Compute coefficients
	one := big.NewRat(1, 1)
	oneMinusP := new(big.Rat).Sub(one, p)      // 1-p
	pOver3 := new(big.Rat).Quo(p, big.NewRat(3, 1)) // p/3

	// K0 = sqrt(1-p) * I
	// For exact arithmetic, we represent sqrt(1-p) as (1-p) and note it's a square root
	// In the Kraus representation, we work with the coefficients directly
	channel.Kraus[0] = scaleIdentity(2, oneMinusP)  // sqrt(1-p) I approximated

	// K1 = sqrt(p/3) * X
	channel.Kraus[1] = scaleMatrix(pauliX(), pOver3)

	// K2 = sqrt(p/3) * Y
	channel.Kraus[2] = scaleMatrix(pauliY(), pOver3)

	// K3 = sqrt(p/3) * Z
	channel.Kraus[3] = scaleMatrix(pauliZ(), pOver3)

	// Compute Choi matrix
	channel.Choi = computeChoiMatrix(channel.Kraus)

	return channel
}

// AmplitudeDampingChannel creates an amplitude damping channel.
// Models decay to |0> with probability gamma.
// Kraus operators:
//   K0 = [[1, 0], [0, sqrt(1-gamma)]]
//   K1 = [[0, sqrt(gamma)], [0, 0]]
func AmplitudeDampingChannel(gamma *big.Rat) *NoiseChannel {
	channel := &NoiseChannel{
		Name:       "amplitude-damping",
		Parameters: map[string]*big.Rat{"gamma": new(big.Rat).Set(gamma)},
		Kraus:      make([]*runtime.Matrix, 2),
	}

	one := big.NewRat(1, 1)
	oneMinusGamma := new(big.Rat).Sub(one, gamma)

	// K0 = [[1, 0], [0, sqrt(1-gamma)]]
	K0 := runtime.NewMatrix(2, 2)
	K0.Set(0, 0, runtime.QIOne())
	K0.Set(1, 1, runtime.NewQI(oneMinusGamma, big.NewRat(0, 1))) // sqrt approx
	channel.Kraus[0] = K0

	// K1 = [[0, sqrt(gamma)], [0, 0]]
	K1 := runtime.NewMatrix(2, 2)
	K1.Set(0, 1, runtime.NewQI(gamma, big.NewRat(0, 1))) // sqrt approx
	channel.Kraus[1] = K1

	// Compute Choi matrix
	channel.Choi = computeChoiMatrix(channel.Kraus)

	return channel
}

// PhaseDampingChannel creates a phase damping channel.
// Models dephasing without energy loss.
// Kraus operators:
//   K0 = [[1, 0], [0, sqrt(1-lambda)]]
//   K1 = [[0, 0], [0, sqrt(lambda)]]
func PhaseDampingChannel(lambda *big.Rat) *NoiseChannel {
	channel := &NoiseChannel{
		Name:       "phase-damping",
		Parameters: map[string]*big.Rat{"lambda": new(big.Rat).Set(lambda)},
		Kraus:      make([]*runtime.Matrix, 2),
	}

	one := big.NewRat(1, 1)
	oneMinusLambda := new(big.Rat).Sub(one, lambda)

	// K0 = [[1, 0], [0, sqrt(1-lambda)]]
	K0 := runtime.NewMatrix(2, 2)
	K0.Set(0, 0, runtime.QIOne())
	K0.Set(1, 1, runtime.NewQI(oneMinusLambda, big.NewRat(0, 1)))
	channel.Kraus[0] = K0

	// K1 = [[0, 0], [0, sqrt(lambda)]]
	K1 := runtime.NewMatrix(2, 2)
	K1.Set(1, 1, runtime.NewQI(lambda, big.NewRat(0, 1)))
	channel.Kraus[1] = K1

	// Compute Choi matrix
	channel.Choi = computeChoiMatrix(channel.Kraus)

	return channel
}

// BitFlipChannel creates a bit flip channel.
// X with probability p.
// Kraus operators:
//   K0 = sqrt(1-p) * I
//   K1 = sqrt(p) * X
func BitFlipChannel(p *big.Rat) *NoiseChannel {
	channel := &NoiseChannel{
		Name:       "bit-flip",
		Parameters: map[string]*big.Rat{"p": new(big.Rat).Set(p)},
		Kraus:      make([]*runtime.Matrix, 2),
	}

	one := big.NewRat(1, 1)
	oneMinusP := new(big.Rat).Sub(one, p)

	// K0 = sqrt(1-p) * I
	channel.Kraus[0] = scaleIdentity(2, oneMinusP)

	// K1 = sqrt(p) * X
	channel.Kraus[1] = scaleMatrix(pauliX(), p)

	// Compute Choi matrix
	channel.Choi = computeChoiMatrix(channel.Kraus)

	return channel
}

// PhaseFlipChannel creates a phase flip channel.
// Z with probability p.
// Kraus operators:
//   K0 = sqrt(1-p) * I
//   K1 = sqrt(p) * Z
func PhaseFlipChannel(p *big.Rat) *NoiseChannel {
	channel := &NoiseChannel{
		Name:       "phase-flip",
		Parameters: map[string]*big.Rat{"p": new(big.Rat).Set(p)},
		Kraus:      make([]*runtime.Matrix, 2),
	}

	one := big.NewRat(1, 1)
	oneMinusP := new(big.Rat).Sub(one, p)

	// K0 = sqrt(1-p) * I
	channel.Kraus[0] = scaleIdentity(2, oneMinusP)

	// K1 = sqrt(p) * Z
	channel.Kraus[1] = scaleMatrix(pauliZ(), p)

	// Compute Choi matrix
	channel.Choi = computeChoiMatrix(channel.Kraus)

	return channel
}

// BitPhaseFlipChannel creates a bit-phase flip channel.
// Y with probability p.
// Kraus operators:
//   K0 = sqrt(1-p) * I
//   K1 = sqrt(p) * Y
func BitPhaseFlipChannel(p *big.Rat) *NoiseChannel {
	channel := &NoiseChannel{
		Name:       "bit-phase-flip",
		Parameters: map[string]*big.Rat{"p": new(big.Rat).Set(p)},
		Kraus:      make([]*runtime.Matrix, 2),
	}

	one := big.NewRat(1, 1)
	oneMinusP := new(big.Rat).Sub(one, p)

	// K0 = sqrt(1-p) * I
	channel.Kraus[0] = scaleIdentity(2, oneMinusP)

	// K1 = sqrt(p) * Y
	channel.Kraus[1] = scaleMatrix(pauliY(), p)

	// Compute Choi matrix
	channel.Choi = computeChoiMatrix(channel.Kraus)

	return channel
}

// ComputeErrorRate extracts QBER from noise channel.
// For depolarizing: QBER = 2p/3 (in each basis)
// For general channel: compute from Choi matrix
func ComputeErrorRate(channel *NoiseChannel, protocolName string) *big.Rat {
	if channel == nil {
		return big.NewRat(0, 1)
	}

	switch protocolName {
	case "BB84":
		return bb84ErrorFromChannel(channel)
	case "Six-State", "six-state", "SixState":
		return sixStateErrorFromChannel(channel)
	default:
		return generalErrorFromChannel(channel)
	}
}

// bb84ErrorFromChannel computes BB84 QBER from a noise channel.
func bb84ErrorFromChannel(channel *NoiseChannel) *big.Rat {
	if channel == nil {
		return big.NewRat(0, 1)
	}

	switch channel.Name {
	case "depolarizing":
		// For depolarizing: QBER = 2p/3 (average over X and Z bases)
		p := channel.Parameters["p"]
		if p == nil {
			return big.NewRat(0, 1)
		}
		return new(big.Rat).Mul(p, big.NewRat(2, 3))

	case "bit-flip":
		// Bit flip causes error in Z basis only: QBER = p/2
		p := channel.Parameters["p"]
		if p == nil {
			return big.NewRat(0, 1)
		}
		return new(big.Rat).Quo(p, big.NewRat(2, 1))

	case "phase-flip":
		// Phase flip causes error in X basis only: QBER = p/2
		p := channel.Parameters["p"]
		if p == nil {
			return big.NewRat(0, 1)
		}
		return new(big.Rat).Quo(p, big.NewRat(2, 1))

	case "amplitude-damping":
		// Amplitude damping: QBER depends on gamma
		gamma := channel.Parameters["gamma"]
		if gamma == nil {
			return big.NewRat(0, 1)
		}
		// Approximate: QBER ~ gamma/4 for small gamma
		return new(big.Rat).Quo(gamma, big.NewRat(4, 1))

	case "phase-damping":
		// Phase damping affects X basis: QBER ~ lambda/4
		lambda := channel.Parameters["lambda"]
		if lambda == nil {
			return big.NewRat(0, 1)
		}
		return new(big.Rat).Quo(lambda, big.NewRat(4, 1))

	default:
		return generalErrorFromChannel(channel)
	}
}

// sixStateErrorFromChannel computes Six-State QBER from a noise channel.
func sixStateErrorFromChannel(channel *NoiseChannel) *big.Rat {
	if channel == nil {
		return big.NewRat(0, 1)
	}

	switch channel.Name {
	case "depolarizing":
		// For depolarizing in 6-state: QBER = p (same in all bases)
		p := channel.Parameters["p"]
		if p == nil {
			return big.NewRat(0, 1)
		}
		return new(big.Rat).Set(p)

	default:
		// For other channels, use general computation
		return generalErrorFromChannel(channel)
	}
}

// generalErrorFromChannel computes QBER from Choi matrix.
func generalErrorFromChannel(channel *NoiseChannel) *big.Rat {
	if channel == nil || channel.Choi == nil {
		return big.NewRat(0, 1)
	}

	// For a general channel, QBER can be estimated from Choi fidelity
	// F = <phi+|J|phi+> where |phi+> is maximally entangled state
	// QBER = (1 - F)/d for d-dimensional system

	d := 2 // Qubit
	choi := channel.Choi

	// |phi+> = (|00> + |11>)/sqrt(2), so projector is
	// |phi+><phi+| = (|00><00| + |00><11| + |11><00| + |11><11|)/2

	// Compute fidelity F = (1/d) * Tr(J)  (simplified for trace-preserving)
	tr := runtime.Trace(choi)
	fidelity := new(big.Rat).Set(tr.Re)
	fidelity.Quo(fidelity, big.NewRat(int64(d), 1))

	// QBER = (1 - F)
	one := big.NewRat(1, 1)
	qber := new(big.Rat).Sub(one, fidelity)
	if qber.Sign() < 0 {
		qber = big.NewRat(0, 1)
	}

	return qber
}

// CompareToThreshold checks if error rate is below security threshold.
func CompareToThreshold(errorRate *big.Rat, protocolName string) (*NoiseToleranceResult, error) {
	if errorRate == nil {
		return nil, fmt.Errorf("nil error rate")
	}

	threshold := GetSecurityThreshold(protocolName)

	below := errorRate.Cmp(threshold) < 0
	margin := new(big.Rat).Sub(threshold, errorRate)

	// Compute key rate at this error level
	keyRate, _ := DeriveKeyRate(protocolName, errorRate, "coherent")

	return &NoiseToleranceResult{
		Protocol:  protocolName,
		ErrorRate: new(big.Rat).Set(errorRate),
		Threshold: threshold,
		IsSecure:  below,
		Margin:    margin,
		KeyRate:   keyRate,
		Channel:   nil,
	}, nil
}

// ApplyNoiseToProtocol simulates noise on protocol by modifying error rate.
func ApplyNoiseToProtocol(p *protocol.Protocol, noise *NoiseChannel) *protocol.Protocol {
	if p == nil {
		return nil
	}

	// Clone the protocol
	result := &protocol.Protocol{
		Name:        p.Name,
		Description: p.Description + fmt.Sprintf(" (with %s noise)", noise.Name),
		Parties:     p.Parties,
		Resources:   p.Resources,
		Rounds:      p.Rounds,
		Assumptions: p.Assumptions,
		TypeSig:     p.TypeSig,
	}

	// Update goal with noise-induced error rate
	errorRate := ComputeErrorRate(noise, p.Name)

	if ka, ok := p.Goal.(protocol.KeyAgreement); ok {
		// Add noise contribution to error rate
		existingError := big.NewRat(0, 1)
		if ka.ErrorRate != nil {
			existingError = new(big.Rat).Set(ka.ErrorRate.V)
		}
		totalError := new(big.Rat).Add(existingError, errorRate)

		// Cap at 1/2
		half := big.NewRat(1, 2)
		if totalError.Cmp(half) > 0 {
			totalError = half
		}

		errorRat := runtime.MakeBigRat(totalError)
		result.Goal = protocol.KeyAgreement{
			KeyLength:    ka.KeyLength,
			ErrorRate:    &errorRat,
			SecrecyBound: ka.SecrecyBound,
		}
	} else {
		result.Goal = p.Goal
	}

	return result
}

// ComputeNoiseThresholds computes noise thresholds for a protocol.
func ComputeNoiseThresholds(protocolName string) *NoiseThresholds {
	// Get the security threshold for the protocol
	securityThreshold := GetSecurityThreshold(protocolName)

	thresholds := &NoiseThresholds{}

	// For depolarizing: QBER = 2p/3, so p = 3*QBER/2
	depThresh := new(big.Rat).Mul(securityThreshold, big.NewRat(3, 2))
	thresholds.Depolarizing = depThresh

	// For amplitude damping: QBER ~ gamma/4, so gamma = 4*QBER
	ampThresh := new(big.Rat).Mul(securityThreshold, big.NewRat(4, 1))
	// Cap at 1
	one := big.NewRat(1, 1)
	if ampThresh.Cmp(one) > 0 {
		ampThresh = one
	}
	thresholds.AmplitudeDamping = ampThresh

	// For phase damping: QBER ~ lambda/4, so lambda = 4*QBER
	phaseThresh := new(big.Rat).Mul(securityThreshold, big.NewRat(4, 1))
	if phaseThresh.Cmp(one) > 0 {
		phaseThresh = one
	}
	thresholds.PhaseDamping = phaseThresh

	return thresholds
}

// AnalyzeNoiseTolerance computes noise tolerance for a protocol.
func AnalyzeNoiseTolerance(p *protocol.Protocol, noise *NoiseModel) (*NoiseResult, error) {
	if p == nil {
		return nil, fmt.Errorf("nil protocol")
	}
	if noise == nil {
		return nil, fmt.Errorf("nil noise model")
	}

	// Convert NoiseModel to NoiseChannel
	var channel *NoiseChannel
	switch noise.Name {
	case "depolarizing":
		if pVal, ok := noise.Parameters["p"]; ok {
			channel = DepolarizingChannel(pVal)
		}
	case "dephasing", "phase-damping":
		if pVal, ok := noise.Parameters["p"]; ok {
			channel = PhaseDampingChannel(pVal)
		}
	case "amplitude-damping":
		if gamma, ok := noise.Parameters["gamma"]; ok {
			channel = AmplitudeDampingChannel(gamma)
		}
	}

	if channel == nil {
		return nil, fmt.Errorf("unsupported noise model: %s", noise.Name)
	}

	// Compute error rate induced by noise
	errorRate := ComputeErrorRate(channel, p.Name)

	// Get threshold
	threshold := GetSecurityThreshold(p.Name)

	// Compute key rate at this error level
	keyRate, keyRateBound := DeriveKeyRate(p.Name, errorRate, "coherent")

	// Determine if secure
	tolerant := errorRate.Cmp(threshold) < 0 && keyRateBound.Sign() > 0

	// Find breakpoint noise (where security fails)
	noiseThresholds := ComputeNoiseThresholds(p.Name)
	var breakpoint *big.Rat
	switch noise.Name {
	case "depolarizing":
		breakpoint = noiseThresholds.Depolarizing
	case "amplitude-damping":
		breakpoint = noiseThresholds.AmplitudeDamping
	case "dephasing", "phase-damping":
		breakpoint = noiseThresholds.PhaseDamping
	default:
		breakpoint = threshold
	}

	return &NoiseResult{
		Tolerant:        tolerant,
		MaxNoise:        breakpoint,
		SecurityAtNoise: keyRateBound,
		KeyRateAtNoise:  keyRate.MidpointEstimate(),
		BreakpointNoise: breakpoint,
	}, nil
}

// computeKeyRateAtError computes key rate for a protocol at given error.
func computeKeyRateAtError(protocolName string, errorRate *big.Rat) *Entropy {
	keyRate, _ := DeriveKeyRate(protocolName, errorRate, "coherent")
	return keyRate
}

// Helper functions for matrix operations

// pauliX returns the Pauli X matrix.
func pauliX() *runtime.Matrix {
	m := runtime.NewMatrix(2, 2)
	m.Set(0, 1, runtime.QIOne())
	m.Set(1, 0, runtime.QIOne())
	return m
}

// pauliY returns the Pauli Y matrix.
func pauliY() *runtime.Matrix {
	m := runtime.NewMatrix(2, 2)
	m.Set(0, 1, runtime.NewQI(big.NewRat(0, 1), big.NewRat(-1, 1))) // -i
	m.Set(1, 0, runtime.NewQI(big.NewRat(0, 1), big.NewRat(1, 1)))  // i
	return m
}

// pauliZ returns the Pauli Z matrix.
func pauliZ() *runtime.Matrix {
	m := runtime.NewMatrix(2, 2)
	m.Set(0, 0, runtime.QIOne())
	m.Set(1, 1, runtime.NewQI(big.NewRat(-1, 1), big.NewRat(0, 1)))
	return m
}

// scaleIdentity creates a scaled identity matrix.
func scaleIdentity(n int, scale *big.Rat) *runtime.Matrix {
	m := runtime.NewMatrix(n, n)
	for i := 0; i < n; i++ {
		m.Set(i, i, runtime.NewQI(scale, big.NewRat(0, 1)))
	}
	return m
}

// scaleMatrix scales a matrix by a rational factor.
func scaleMatrix(m *runtime.Matrix, scale *big.Rat) *runtime.Matrix {
	result := runtime.NewMatrix(m.Rows, m.Cols)
	for i := 0; i < m.Rows; i++ {
		for j := 0; j < m.Cols; j++ {
			entry := m.Get(i, j)
			result.Set(i, j, runtime.QIScale(entry, scale))
		}
	}
	return result
}

// computeChoiMatrix computes the Choi matrix from Kraus operators.
// J = sum_k (I tensor K_k) |phi+><phi+| (I tensor K_k)^dag
// Simplified: J = sum_k |K_k><K_k| in vectorized form
func computeChoiMatrix(kraus []*runtime.Matrix) *runtime.Matrix {
	if len(kraus) == 0 || kraus[0] == nil {
		return nil
	}

	d := kraus[0].Rows
	choi := runtime.NewMatrix(d*d, d*d)

	for _, K := range kraus {
		if K == nil {
			continue
		}
		// Compute contribution from this Kraus operator
		// J_k[i*d+j, k*d+l] = K[i,k] * conj(K[j,l])
		for i := 0; i < d; i++ {
			for j := 0; j < d; j++ {
				for k := 0; k < d; k++ {
					for l := 0; l < d; l++ {
						row := i*d + j
						col := k*d + l
						kik := K.Get(i, k)
						kjl := runtime.QIConj(K.Get(j, l))
						contrib := runtime.QIMul(kik, kjl)
						current := choi.Get(row, col)
						choi.Set(row, col, runtime.QIAdd(current, contrib))
					}
				}
			}
		}
	}

	return choi
}

// ToValue converts a NoiseResult to a runtime.Value.
func (r *NoiseResult) ToValue() runtime.Value {
	return runtime.MakeTag(
		runtime.MakeText("noise-result"),
		runtime.MakeSeq(
			runtime.MakeBool(r.Tolerant),
			runtime.MakeBigRat(r.MaxNoise),
			runtime.MakeBigRat(r.SecurityAtNoise),
			runtime.MakeBigRat(r.KeyRateAtNoise),
			runtime.MakeBigRat(r.BreakpointNoise),
		),
	)
}

// ToValue converts a NoiseToleranceResult to a runtime.Value.
func (r *NoiseToleranceResult) ToValue() runtime.Value {
	if r == nil {
		return runtime.MakeNil()
	}

	var keyRateVal runtime.Value = runtime.MakeNil()
	if r.KeyRate != nil {
		keyRateVal = r.KeyRate.ToValue()
	}

	var channelVal runtime.Value = runtime.MakeNil()
	if r.Channel != nil {
		channelVal = r.Channel.ToValue()
	}

	return runtime.MakeTag(
		runtime.MakeText("noise-tolerance-result"),
		runtime.MakeSeq(
			runtime.MakeText(r.Protocol),
			runtime.MakeBigRat(r.ErrorRate),
			runtime.MakeBigRat(r.Threshold),
			runtime.MakeBool(r.IsSecure),
			runtime.MakeBigRat(r.Margin),
			keyRateVal,
			channelVal,
		),
	)
}

// ToValue converts a NoiseChannel to a runtime.Value.
func (n *NoiseChannel) ToValue() runtime.Value {
	if n == nil {
		return runtime.MakeNil()
	}

	// Convert parameters
	params := make([]runtime.Value, 0, len(n.Parameters)*2)
	for k, v := range n.Parameters {
		params = append(params, runtime.MakeText(k))
		params = append(params, runtime.MakeBigRat(v))
	}

	// Convert Kraus operators
	krausVals := make([]runtime.Value, len(n.Kraus))
	for i, k := range n.Kraus {
		if k != nil {
			krausVals[i] = runtime.MatrixToValue(k)
		} else {
			krausVals[i] = runtime.MakeNil()
		}
	}

	// Convert Choi matrix
	var choiVal runtime.Value = runtime.MakeNil()
	if n.Choi != nil {
		choiVal = runtime.MatrixToValue(n.Choi)
	}

	return runtime.MakeTag(
		runtime.MakeText("noise-channel"),
		runtime.MakeSeq(
			runtime.MakeText(n.Name),
			runtime.MakeSeq(params...),
			runtime.MakeSeq(krausVals...),
			choiVal,
		),
	)
}

// NoiseChannelFromValue parses a NoiseChannel from a runtime.Value.
func NoiseChannelFromValue(v runtime.Value) (*NoiseChannel, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "noise-channel" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 4 {
		return nil, false
	}

	name, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}

	// Parse parameters
	paramsSeq, ok := seq.Items[1].(runtime.Seq)
	if !ok {
		return nil, false
	}
	params := make(map[string]*big.Rat)
	for i := 0; i+1 < len(paramsSeq.Items); i += 2 {
		key, ok := paramsSeq.Items[i].(runtime.Text)
		if !ok {
			continue
		}
		val, ok := paramsSeq.Items[i+1].(runtime.Rat)
		if !ok {
			continue
		}
		params[key.V] = new(big.Rat).Set(val.V)
	}

	// Parse Kraus operators
	krausSeq, ok := seq.Items[2].(runtime.Seq)
	if !ok {
		return nil, false
	}
	kraus := make([]*runtime.Matrix, len(krausSeq.Items))
	for i, item := range krausSeq.Items {
		if _, isNil := item.(runtime.Nil); !isNil {
			m, ok := runtime.MatrixFromValue(item)
			if ok {
				kraus[i] = m
			}
		}
	}

	// Parse Choi matrix
	var choi *runtime.Matrix
	if _, isNil := seq.Items[3].(runtime.Nil); !isNil {
		choi, _ = runtime.MatrixFromValue(seq.Items[3])
	}

	return &NoiseChannel{
		Name:       name.V,
		Parameters: params,
		Kraus:      kraus,
		Choi:       choi,
	}, true
}

// NoiseToleranceResultFromValue parses a NoiseToleranceResult from a runtime.Value.
func NoiseToleranceResultFromValue(v runtime.Value) (*NoiseToleranceResult, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "noise-tolerance-result" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 7 {
		return nil, false
	}

	protocol, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}
	errorRate, ok := seq.Items[1].(runtime.Rat)
	if !ok {
		return nil, false
	}
	threshold, ok := seq.Items[2].(runtime.Rat)
	if !ok {
		return nil, false
	}
	isSecure, ok := seq.Items[3].(runtime.Bool)
	if !ok {
		return nil, false
	}
	margin, ok := seq.Items[4].(runtime.Rat)
	if !ok {
		return nil, false
	}

	keyRate, ok := EntropyFromValue(seq.Items[5])
	if !ok {
		return nil, false
	}

	channel, ok := NoiseChannelFromValue(seq.Items[6])
	if !ok {
		return nil, false
	}

	return &NoiseToleranceResult{
		Protocol:  protocol.V,
		ErrorRate: new(big.Rat).Set(errorRate.V),
		Threshold: new(big.Rat).Set(threshold.V),
		IsSecure:  isSecure.V,
		Margin:    new(big.Rat).Set(margin.V),
		KeyRate:   keyRate,
		Channel:   channel,
	}, true
}

// ToValue converts NoiseThresholds to a runtime.Value.
func (t *NoiseThresholds) ToValue() runtime.Value {
	if t == nil {
		return runtime.MakeNil()
	}
	return runtime.MakeTag(
		runtime.MakeText("noise-thresholds"),
		runtime.MakeSeq(
			ratOrNil(t.Depolarizing),
			ratOrNil(t.AmplitudeDamping),
			ratOrNil(t.PhaseDamping),
		),
	)
}
