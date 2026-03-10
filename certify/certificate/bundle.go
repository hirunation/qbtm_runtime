// bundle.go provides comprehensive certificate bundle generation.
//
// This file implements the full analysis pipeline that produces
// complete certificate bundles for quantum protocols, including
// correctness verification, security analysis, noise tolerance,
// and attack resistance.
package certificate

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"qbtm/certify/analysis"
	"qbtm/certify/attack"
	"qbtm/certify/protocol"
	"qbtm/certify/protocol/communication"
	"qbtm/certify/protocol/cryptographic"
	"qbtm/certify/protocol/multiparty"
	"qbtm/certify/protocol/qkd"
	"qbtm/runtime"
)

// AnalysisOptions configures full analysis parameters.
type AnalysisOptions struct {
	ErrorRate       *big.Rat // Observed/assumed error rate
	AdversaryModels []string // "individual", "collective", "coherent"
	NoiseModels     []string // "depolarizing", "amplitude_damping", "phase_damping"
	IncludeAttacks  bool     // Include attack library analysis
	IncludeCircuit  bool     // Include synthesized circuit
	Verbose         bool     // Include derivation details
}

// DefaultAnalysisOptions returns the default analysis configuration.
func DefaultAnalysisOptions() *AnalysisOptions {
	return &AnalysisOptions{
		ErrorRate:       big.NewRat(0, 1), // Assume perfect
		AdversaryModels: []string{"individual", "collective", "coherent"},
		NoiseModels:     []string{"depolarizing"},
		IncludeAttacks:  true,
		IncludeCircuit:  true,
		Verbose:         false,
	}
}

// FullAnalysisBundle contains complete analysis results for a protocol.
type FullAnalysisBundle struct {
	Protocol  string
	Timestamp int64

	// Protocol synthesis
	CircuitQGID  [32]byte
	CircuitValue runtime.Value

	// Correctness
	CorrectnessEvidence *Evidence
	IdealChannelChoi    *runtime.Matrix

	// Security (per adversary model)
	SecurityEvidence map[string]*Evidence // adversary model -> evidence

	// Noise tolerance (per noise model)
	NoiseEvidence map[string]*Evidence // noise model -> evidence

	// Attack library
	ApplicableAttacks []attack.Attack
	AttackEvidence    []*Evidence

	// Summary
	IsSecure          bool
	SecurityThreshold *big.Rat
	KeyRate           *analysis.Entropy

	// Full bundle
	Bundle *Bundle
}

// GenerateFullAnalysis produces a complete certificate bundle for a protocol.
func GenerateFullAnalysis(protocolName string, opts *AnalysisOptions) (*FullAnalysisBundle, error) {
	if opts == nil {
		opts = DefaultAnalysisOptions()
	}

	result := &FullAnalysisBundle{
		Protocol:         protocolName,
		Timestamp:        time.Now().Unix(),
		SecurityEvidence: make(map[string]*Evidence),
		NoiseEvidence:    make(map[string]*Evidence),
	}

	// 1. Get protocol specification
	synth, err := GetProtocol(protocolName)
	if err != nil {
		return nil, fmt.Errorf("failed to get protocol %s: %w", protocolName, err)
	}

	proto := synth.Protocol()
	if proto == nil {
		return nil, fmt.Errorf("protocol synthesizer returned nil protocol")
	}

	// 2. Synthesize circuit
	if opts.IncludeCircuit {
		store := runtime.NewStore()
		qgid, synthErr := synth.Synthesize(store)
		if synthErr == nil {
			result.CircuitQGID = qgid
			if val, ok := store.GetValue(qgid); ok {
				result.CircuitValue = val
			}
		}
		// Continue even if synthesis fails - we can still do analysis
	}

	// 3. Correctness verification
	store := runtime.NewStore()
	correctnessResult, err := analysis.VerifyCorrectness(proto, store)
	if err == nil && correctnessResult != nil {
		result.CorrectnessEvidence = CreateFromCorrectnessResult(
			correctnessResult.Correct,
			correctnessResult.Fidelity,
			correctnessResult.ChoiMatrix,
			correctnessResult.IdealChannel,
		)
		result.IdealChannelChoi = correctnessResult.IdealChannel
	}

	// 4. Security analysis for each adversary model
	for _, model := range opts.AdversaryModels {
		secResult, secErr := computeSecurityForModel(proto, opts.ErrorRate, model)
		if secErr != nil {
			continue // Skip failed analyses
		}

		result.SecurityEvidence[model] = CreateFromSecurityResult(
			proto.Name,
			model,
			secResult.KeyRateBound,
			secResult.Threshold,
			secResult.IsSecure,
		)

		if secResult.KeyRate != nil && result.KeyRate == nil {
			result.KeyRate = secResult.KeyRate
		}
	}

	// 5. Noise tolerance analysis
	for _, noiseModel := range opts.NoiseModels {
		noiseChannel := getNoiseChannel(noiseModel, opts.ErrorRate)
		if noiseChannel == nil {
			continue
		}

		noiseResult, noiseErr := analyzeNoiseWithChannel(proto, noiseChannel)
		if noiseErr != nil {
			continue
		}

		result.NoiseEvidence[noiseModel] = CreateFromNoiseResult(
			proto.Name,
			opts.ErrorRate,
			noiseResult.Threshold,
			noiseResult.IsSecure,
			noiseResult.Margin,
			noiseModel,
		)
	}

	// 6. Attack library
	if opts.IncludeAttacks {
		result.ApplicableAttacks = attack.AttacksForProtocol(protocolName)
		for _, atk := range result.ApplicableAttacks {
			ev := CreateFromAttackAnalysis(
				protocolName,
				atk.Name(),
				atk.InformationGained(),
				atk.DisturbanceInduced(),
				atk.DisturbanceInduced().Sign() > 0,
			)
			result.AttackEvidence = append(result.AttackEvidence, ev)
		}
	}

	// 7. Determine overall security
	threshold := analysis.GetSecurityThreshold(protocolName)
	result.SecurityThreshold = threshold
	if threshold != nil && opts.ErrorRate != nil {
		result.IsSecure = opts.ErrorRate.Cmp(threshold) < 0
	}

	// 8. Build bundle
	result.Bundle = NewBundle(protocolName)
	result.Bundle.Metadata["timestamp"] = fmt.Sprintf("%d", result.Timestamp)
	result.Bundle.Metadata["error_rate"] = opts.ErrorRate.RatString()

	if result.CorrectnessEvidence != nil {
		result.Bundle.AddEvidence(result.CorrectnessEvidence)
	}
	for model, ev := range result.SecurityEvidence {
		if ev != nil {
			ev.Claim.Protocol = protocolName
			result.Bundle.Metadata["security_model_"+model] = ev.Status.String()
			result.Bundle.AddEvidence(ev)
		}
	}
	for model, ev := range result.NoiseEvidence {
		if ev != nil {
			ev.Claim.Protocol = protocolName
			result.Bundle.Metadata["noise_model_"+model] = ev.Status.String()
			result.Bundle.AddEvidence(ev)
		}
	}
	for _, ev := range result.AttackEvidence {
		if ev != nil {
			result.Bundle.AddEvidence(ev)
		}
	}

	return result, nil
}

// computeSecurityForModel computes security bounds for a specific adversary model.
func computeSecurityForModel(p *protocol.Protocol, errorRate *big.Rat, model string) (*analysis.SecurityResult, error) {
	// Get key rate for this model
	keyRate, keyRateBound := analysis.DeriveKeyRate(p.Name, errorRate, model)

	// Get threshold
	threshold := analysis.GetSecurityThreshold(p.Name)

	// Determine if secure
	isSecure := errorRate.Cmp(threshold) < 0 && keyRateBound.Sign() > 0

	return &analysis.SecurityResult{
		Protocol:       p.Name,
		AdversaryModel: model,
		KeyRate:        keyRate,
		KeyRateBound:   keyRateBound,
		Threshold:      threshold,
		IsSecure:       isSecure,
	}, nil
}

// getNoiseChannel creates a noise channel for the given model and error rate.
func getNoiseChannel(noiseModel string, errorRate *big.Rat) *analysis.NoiseChannel {
	switch noiseModel {
	case "depolarizing":
		// Convert error rate to depolarizing parameter
		// QBER = 2p/3 for depolarizing, so p = 3*QBER/2
		p := new(big.Rat).Mul(errorRate, big.NewRat(3, 2))
		one := big.NewRat(1, 1)
		if p.Cmp(one) > 0 {
			p = one
		}
		return analysis.DepolarizingChannel(p)

	case "amplitude_damping":
		// gamma = 4*QBER for amplitude damping approximation
		gamma := new(big.Rat).Mul(errorRate, big.NewRat(4, 1))
		one := big.NewRat(1, 1)
		if gamma.Cmp(one) > 0 {
			gamma = one
		}
		return analysis.AmplitudeDampingChannel(gamma)

	case "phase_damping":
		// lambda = 4*QBER for phase damping approximation
		lambda := new(big.Rat).Mul(errorRate, big.NewRat(4, 1))
		one := big.NewRat(1, 1)
		if lambda.Cmp(one) > 0 {
			lambda = one
		}
		return analysis.PhaseDampingChannel(lambda)

	case "bit_flip":
		return analysis.BitFlipChannel(errorRate)

	case "phase_flip":
		return analysis.PhaseFlipChannel(errorRate)

	default:
		return nil
	}
}

// analyzeNoiseWithChannel performs noise tolerance analysis.
func analyzeNoiseWithChannel(p *protocol.Protocol, channel *analysis.NoiseChannel) (*analysis.NoiseToleranceResult, error) {
	if channel == nil {
		return nil, fmt.Errorf("nil noise channel")
	}

	// Compute error rate induced by noise
	errorRate := analysis.ComputeErrorRate(channel, p.Name)

	// Get threshold
	threshold := analysis.GetSecurityThreshold(p.Name)

	// Compute key rate at this error level
	keyRate, _ := analysis.DeriveKeyRate(p.Name, errorRate, "coherent")

	// Determine if secure
	isSecure := errorRate.Cmp(threshold) < 0

	// Compute margin
	margin := new(big.Rat).Sub(threshold, errorRate)

	return &analysis.NoiseToleranceResult{
		Protocol:  p.Name,
		ErrorRate: errorRate,
		Threshold: threshold,
		IsSecure:  isSecure,
		Margin:    margin,
		KeyRate:   keyRate,
		Channel:   channel,
	}, nil
}

// GetProtocol returns a protocol synthesizer by name.
func GetProtocol(name string) (protocol.ProtocolSynthesizer, error) {
	switch name {
	// QKD protocols
	case "BB84":
		return qkd.NewBB84(100), nil
	case "E91":
		return qkd.NewE91(100), nil
	case "B92":
		return qkd.NewB92(100), nil
	case "Six-State":
		return qkd.NewSixState(100), nil
	case "SARG04":
		return qkd.NewSARG04(100), nil

	// Communication protocols
	case "Teleportation":
		return communication.NewTeleportation(), nil
	case "SuperdenseCoding":
		return communication.NewSuperdenseCoding(), nil
	case "EntanglementSwapping":
		return communication.NewEntanglementSwapping(), nil

	// Multiparty protocols
	case "GHZ":
		return multiparty.NewGHZ(3), nil
	case "W-State":
		return multiparty.NewWState(3), nil
	case "SecretSharing":
		return multiparty.NewSecretSharing(2, 3), nil

	// Cryptographic protocols
	case "CoinFlip":
		return cryptographic.NewCoinFlip(), nil
	case "BitCommitment":
		return cryptographic.NewBitCommitmentBalanced(), nil
	case "ObliviousTransfer":
		return cryptographic.NewObliviousTransferIdeal(), nil

	default:
		return nil, fmt.Errorf("unknown protocol: %s", name)
	}
}

// RegisteredProtocols returns the list of all known protocols.
func RegisteredProtocols() []string {
	return []string{
		// QKD
		"BB84",
		"E91",
		"B92",
		"Six-State",
		"SARG04",
		// Communication
		"Teleportation",
		"SuperdenseCoding",
		"EntanglementSwapping",
		// Multiparty
		"GHZ",
		"W-State",
		"SecretSharing",
		// Cryptographic
		"CoinFlip",
		"BitCommitment",
		"ObliviousTransfer",
	}
}

// ProtocolMetadata contains information about a protocol.
type ProtocolMetadata struct {
	Name            string
	Category        string
	Description     string
	SecurityGoal    string
	Threshold       *big.Rat
	KeyRateFormula  string
	DefaultNumBits  int
	Assumptions     []string
}

// ProtocolInfo returns metadata about a protocol.
func ProtocolInfo(name string) *ProtocolMetadata {
	switch name {
	case "BB84":
		return &ProtocolMetadata{
			Name:           "BB84",
			Category:       "QKD",
			Description:    "Bennett-Brassard 1984 quantum key distribution protocol",
			SecurityGoal:   "Key Agreement",
			Threshold:      big.NewRat(11, 100),
			KeyRateFormula: "r = 1 - 2h(e)",
			DefaultNumBits: 100,
			Assumptions:    []string{"No-Cloning", "Authenticated Classical Channel"},
		}
	case "E91":
		return &ProtocolMetadata{
			Name:           "E91",
			Category:       "QKD",
			Description:    "Ekert 1991 entanglement-based QKD protocol",
			SecurityGoal:   "Key Agreement",
			Threshold:      big.NewRat(11, 100),
			KeyRateFormula: "r = 1 - h((1+sqrt((S/2)^2-1))/2)",
			DefaultNumBits: 100,
			Assumptions:    []string{"No-Cloning", "Authenticated Classical Channel", "Entanglement Source"},
		}
	case "B92":
		return &ProtocolMetadata{
			Name:           "B92",
			Category:       "QKD",
			Description:    "Bennett 1992 two-state QKD protocol",
			SecurityGoal:   "Key Agreement",
			Threshold:      big.NewRat(1, 4),
			KeyRateFormula: "r = 1/2 * (1 - h(2e))",
			DefaultNumBits: 100,
			Assumptions:    []string{"No-Cloning", "Authenticated Classical Channel"},
		}
	case "Six-State":
		return &ProtocolMetadata{
			Name:           "Six-State",
			Category:       "QKD",
			Description:    "Six-state QKD protocol with three conjugate bases",
			SecurityGoal:   "Key Agreement",
			Threshold:      big.NewRat(1, 6),
			KeyRateFormula: "r = 1 - (5/3)h(3e/2)",
			DefaultNumBits: 100,
			Assumptions:    []string{"No-Cloning", "Authenticated Classical Channel"},
		}
	case "SARG04":
		return &ProtocolMetadata{
			Name:           "SARG04",
			Category:       "QKD",
			Description:    "SARG04 protocol resistant to photon-number splitting",
			SecurityGoal:   "Key Agreement",
			Threshold:      big.NewRat(10, 100),
			KeyRateFormula: "r = 1 - 2h(e) - f(mu)",
			DefaultNumBits: 100,
			Assumptions:    []string{"No-Cloning", "Authenticated Classical Channel", "Weak Coherent Source"},
		}
	case "Teleportation":
		return &ProtocolMetadata{
			Name:         "Teleportation",
			Category:     "Communication",
			Description:  "Quantum teleportation protocol",
			SecurityGoal: "State Transfer",
			Assumptions:  []string{"Pre-shared Entanglement", "Classical Communication"},
		}
	case "SuperdenseCoding":
		return &ProtocolMetadata{
			Name:         "SuperdenseCoding",
			Category:     "Communication",
			Description:  "Superdense coding protocol for 2 classical bits per qubit",
			SecurityGoal: "State Transfer",
			Assumptions:  []string{"Pre-shared Entanglement"},
		}
	case "EntanglementSwapping":
		return &ProtocolMetadata{
			Name:         "EntanglementSwapping",
			Category:     "Communication",
			Description:  "Entanglement swapping for quantum repeaters",
			SecurityGoal: "State Transfer",
			Assumptions:  []string{"Two Entangled Pairs", "Bell Measurement"},
		}
	case "GHZ":
		return &ProtocolMetadata{
			Name:         "GHZ",
			Category:     "Multiparty",
			Description:  "GHZ state distribution protocol",
			SecurityGoal: "State Transfer",
			Assumptions:  []string{"Multiparty Quantum Channels"},
		}
	case "W-State":
		return &ProtocolMetadata{
			Name:         "W-State",
			Category:     "Multiparty",
			Description:  "W state distribution protocol",
			SecurityGoal: "State Transfer",
			Assumptions:  []string{"Multiparty Quantum Channels"},
		}
	case "SecretSharing":
		return &ProtocolMetadata{
			Name:         "SecretSharing",
			Category:     "Multiparty",
			Description:  "Quantum secret sharing protocol",
			SecurityGoal: "Secret Sharing",
			Assumptions:  []string{"Multiparty Quantum Channels", "Threshold Access Structure"},
		}
	case "CoinFlip":
		return &ProtocolMetadata{
			Name:           "CoinFlip",
			Category:       "Cryptographic",
			Description:    "Quantum coin flipping protocol",
			SecurityGoal:   "Coin Flip",
			KeyRateFormula: "bias >= 1/sqrt(2) - 1/2 (Kitaev bound)",
			Assumptions:    []string{"Quantum Communication"},
		}
	case "BitCommitment":
		return &ProtocolMetadata{
			Name:           "BitCommitment",
			Category:       "Cryptographic",
			Description:    "Quantum bit commitment protocol",
			SecurityGoal:   "Bit Commitment",
			KeyRateFormula: "binding + hiding >= 1 (impossibility)",
			Assumptions:    []string{"Quantum Communication"},
		}
	case "ObliviousTransfer":
		return &ProtocolMetadata{
			Name:         "ObliviousTransfer",
			Category:     "Cryptographic",
			Description:  "Quantum 1-2 oblivious transfer protocol",
			SecurityGoal: "Oblivious Transfer",
			Assumptions:  []string{"Quantum Communication", "Bit Commitment"},
		}
	default:
		return nil
	}
}

// GenerateSummary creates a human-readable summary of the analysis.
func (fab *FullAnalysisBundle) GenerateSummary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Protocol Analysis Summary\n"))
	sb.WriteString(fmt.Sprintf("========================\n\n"))
	sb.WriteString(fmt.Sprintf("Protocol: %s\n", fab.Protocol))
	sb.WriteString(fmt.Sprintf("Timestamp: %d\n", fab.Timestamp))
	sb.WriteString("\n")

	// Correctness
	sb.WriteString("Correctness Verification\n")
	sb.WriteString("------------------------\n")
	if fab.CorrectnessEvidence != nil {
		if fab.CorrectnessEvidence.IsVerified() {
			sb.WriteString("Status: VERIFIED\n")
		} else {
			sb.WriteString(fmt.Sprintf("Status: %s\n", fab.CorrectnessEvidence.Status.String()))
		}
	} else {
		sb.WriteString("Status: NOT ANALYZED\n")
	}
	sb.WriteString("\n")

	// Security by model
	sb.WriteString("Security Analysis\n")
	sb.WriteString("-----------------\n")
	for model, ev := range fab.SecurityEvidence {
		if ev != nil {
			sb.WriteString(fmt.Sprintf("  %s attacks: %s\n", model, ev.Status.String()))
		}
	}
	if len(fab.SecurityEvidence) == 0 {
		sb.WriteString("  No security analysis performed\n")
	}
	sb.WriteString("\n")

	// Noise tolerance
	sb.WriteString("Noise Tolerance\n")
	sb.WriteString("---------------\n")
	for model, ev := range fab.NoiseEvidence {
		if ev != nil {
			sb.WriteString(fmt.Sprintf("  %s noise: %s\n", model, ev.Status.String()))
		}
	}
	if len(fab.NoiseEvidence) == 0 {
		sb.WriteString("  No noise analysis performed\n")
	}
	sb.WriteString("\n")

	// Key rate
	if fab.KeyRate != nil {
		sb.WriteString("Key Rate\n")
		sb.WriteString("--------\n")
		sb.WriteString(fmt.Sprintf("  Symbolic: %s\n", fab.KeyRate.Symbolic))
		sb.WriteString(fmt.Sprintf("  Lower bound: %s\n", fab.KeyRate.Lower.RatString()))
		sb.WriteString(fmt.Sprintf("  Upper bound: %s\n", fab.KeyRate.Upper.RatString()))
		sb.WriteString("\n")
	}

	// Security threshold
	if fab.SecurityThreshold != nil {
		sb.WriteString("Security Threshold\n")
		sb.WriteString("------------------\n")
		sb.WriteString(fmt.Sprintf("  Maximum QBER: %s\n", fab.SecurityThreshold.RatString()))
		sb.WriteString("\n")
	}

	// Attack analysis
	if len(fab.ApplicableAttacks) > 0 {
		sb.WriteString("Attack Analysis\n")
		sb.WriteString("---------------\n")
		for _, atk := range fab.ApplicableAttacks {
			sb.WriteString(fmt.Sprintf("  %s:\n", atk.Name()))
			sb.WriteString(fmt.Sprintf("    Info gained: %s\n", atk.InformationGained().RatString()))
			sb.WriteString(fmt.Sprintf("    Disturbance: %s\n", atk.DisturbanceInduced().RatString()))
		}
		sb.WriteString("\n")
	}

	// Overall
	sb.WriteString("Overall Security\n")
	sb.WriteString("----------------\n")
	if fab.IsSecure {
		sb.WriteString("Status: SECURE\n")
	} else {
		sb.WriteString("Status: NOT SECURE (error rate exceeds threshold)\n")
	}
	sb.WriteString("\n")

	// Bundle verification
	if fab.Bundle != nil {
		sb.WriteString("Certificate Bundle\n")
		sb.WriteString("------------------\n")
		sb.WriteString(fmt.Sprintf("  Evidence items: %d\n", len(fab.Bundle.Evidence)))
		if fab.Bundle.AllVerified() {
			sb.WriteString("  Bundle status: ALL VERIFIED\n")
		} else {
			sb.WriteString("  Bundle status: PARTIAL\n")
		}
	}

	return sb.String()
}

// ToValue converts a FullAnalysisBundle to a runtime.Value.
func (fab *FullAnalysisBundle) ToValue() runtime.Value {
	if fab == nil {
		return runtime.MakeNil()
	}

	// Convert security evidence map
	securityEvItems := make([]runtime.Value, 0, len(fab.SecurityEvidence)*2)
	for model, ev := range fab.SecurityEvidence {
		securityEvItems = append(securityEvItems, runtime.MakeText(model))
		if ev != nil {
			securityEvItems = append(securityEvItems, ev.ToValue())
		} else {
			securityEvItems = append(securityEvItems, runtime.MakeNil())
		}
	}

	// Convert noise evidence map
	noiseEvItems := make([]runtime.Value, 0, len(fab.NoiseEvidence)*2)
	for model, ev := range fab.NoiseEvidence {
		noiseEvItems = append(noiseEvItems, runtime.MakeText(model))
		if ev != nil {
			noiseEvItems = append(noiseEvItems, ev.ToValue())
		} else {
			noiseEvItems = append(noiseEvItems, runtime.MakeNil())
		}
	}

	// Convert attack evidence
	attackEvItems := make([]runtime.Value, len(fab.AttackEvidence))
	for i, ev := range fab.AttackEvidence {
		if ev != nil {
			attackEvItems[i] = ev.ToValue()
		} else {
			attackEvItems[i] = runtime.MakeNil()
		}
	}

	// Convert applicable attacks
	attackNames := make([]runtime.Value, len(fab.ApplicableAttacks))
	for i, atk := range fab.ApplicableAttacks {
		attackNames[i] = runtime.MakeText(atk.Name())
	}

	// Convert correctness evidence
	var correctnessVal runtime.Value = runtime.MakeNil()
	if fab.CorrectnessEvidence != nil {
		correctnessVal = fab.CorrectnessEvidence.ToValue()
	}

	// Convert ideal channel
	var idealChannelVal runtime.Value = runtime.MakeNil()
	if fab.IdealChannelChoi != nil {
		idealChannelVal = runtime.MatrixToValue(fab.IdealChannelChoi)
	}

	// Convert key rate
	var keyRateVal runtime.Value = runtime.MakeNil()
	if fab.KeyRate != nil {
		keyRateVal = fab.KeyRate.ToValue()
	}

	// Convert security threshold
	var thresholdVal runtime.Value = runtime.MakeNil()
	if fab.SecurityThreshold != nil {
		thresholdVal = runtime.MakeBigRat(fab.SecurityThreshold)
	}

	// Convert bundle
	var bundleVal runtime.Value = runtime.MakeNil()
	if fab.Bundle != nil {
		bundleVal = fab.Bundle.ToValue()
	}

	// Convert circuit value
	var circuitVal runtime.Value = runtime.MakeNil()
	if fab.CircuitValue != nil {
		circuitVal = fab.CircuitValue
	}

	return runtime.MakeTag(
		runtime.MakeText("full-analysis-bundle"),
		runtime.MakeSeq(
			runtime.MakeText(fab.Protocol),
			runtime.MakeInt(fab.Timestamp),
			runtime.MakeBytes(fab.CircuitQGID[:]),
			circuitVal,
			correctnessVal,
			idealChannelVal,
			runtime.MakeSeq(securityEvItems...),
			runtime.MakeSeq(noiseEvItems...),
			runtime.MakeSeq(attackNames...),
			runtime.MakeSeq(attackEvItems...),
			runtime.MakeBool(fab.IsSecure),
			thresholdVal,
			keyRateVal,
			bundleVal,
		),
	)
}

// FullAnalysisBundleFromValue deserializes a FullAnalysisBundle from a runtime.Value.
func FullAnalysisBundleFromValue(v runtime.Value) (*FullAnalysisBundle, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "full-analysis-bundle" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 14 {
		return nil, false
	}

	fab := &FullAnalysisBundle{
		SecurityEvidence: make(map[string]*Evidence),
		NoiseEvidence:    make(map[string]*Evidence),
	}

	// Parse protocol name
	protocol, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}
	fab.Protocol = protocol.V

	// Parse timestamp
	timestamp, ok := seq.Items[1].(runtime.Int)
	if !ok {
		return nil, false
	}
	fab.Timestamp = timestamp.V.Int64()

	// Parse circuit QGID
	qgidBytes, ok := seq.Items[2].(runtime.Bytes)
	if ok && len(qgidBytes.V) == 32 {
		copy(fab.CircuitQGID[:], qgidBytes.V)
	}

	// Parse circuit value (item 3)
	if _, isNil := seq.Items[3].(runtime.Nil); !isNil {
		fab.CircuitValue = seq.Items[3]
	}

	// Parse correctness evidence
	if _, isNil := seq.Items[4].(runtime.Nil); !isNil {
		fab.CorrectnessEvidence, _ = EvidenceFromValue(seq.Items[4])
	}

	// Parse ideal channel (item 5)
	if _, isNil := seq.Items[5].(runtime.Nil); !isNil {
		fab.IdealChannelChoi, _ = runtime.MatrixFromValue(seq.Items[5])
	}

	// Parse security evidence map (item 6)
	if secSeq, ok := seq.Items[6].(runtime.Seq); ok {
		for i := 0; i+1 < len(secSeq.Items); i += 2 {
			key, ok := secSeq.Items[i].(runtime.Text)
			if !ok {
				continue
			}
			ev, ok := EvidenceFromValue(secSeq.Items[i+1])
			if ok && ev != nil {
				fab.SecurityEvidence[key.V] = ev
			}
		}
	}

	// Parse noise evidence map (item 7)
	if noiseSeq, ok := seq.Items[7].(runtime.Seq); ok {
		for i := 0; i+1 < len(noiseSeq.Items); i += 2 {
			key, ok := noiseSeq.Items[i].(runtime.Text)
			if !ok {
				continue
			}
			ev, ok := EvidenceFromValue(noiseSeq.Items[i+1])
			if ok && ev != nil {
				fab.NoiseEvidence[key.V] = ev
			}
		}
	}

	// Parse attack names (item 8) - we just track names, can't reconstruct full attacks
	// Parse attack evidence (item 9)
	if attackSeq, ok := seq.Items[9].(runtime.Seq); ok {
		for _, item := range attackSeq.Items {
			ev, ok := EvidenceFromValue(item)
			if ok && ev != nil {
				fab.AttackEvidence = append(fab.AttackEvidence, ev)
			}
		}
	}

	// Parse IsSecure
	if isSecure, ok := seq.Items[10].(runtime.Bool); ok {
		fab.IsSecure = isSecure.V
	}

	// Parse threshold (item 11)
	if thresh, ok := seq.Items[11].(runtime.Rat); ok {
		fab.SecurityThreshold = new(big.Rat).Set(thresh.V)
	}

	// Parse key rate (item 12)
	if _, isNil := seq.Items[12].(runtime.Nil); !isNil {
		fab.KeyRate, _ = analysis.EntropyFromValue(seq.Items[12])
	}

	// Parse bundle (item 13)
	if _, isNil := seq.Items[13].(runtime.Nil); !isNil {
		fab.Bundle, _ = BundleFromValue(seq.Items[13])
	}

	return fab, true
}

// GenerateBundleForAllProtocols generates analysis bundles for all registered protocols.
func GenerateBundleForAllProtocols(opts *AnalysisOptions) (map[string]*FullAnalysisBundle, error) {
	result := make(map[string]*FullAnalysisBundle)

	for _, name := range RegisteredProtocols() {
		bundle, err := GenerateFullAnalysis(name, opts)
		if err != nil {
			// Continue with other protocols even if one fails
			continue
		}
		result[name] = bundle
	}

	return result, nil
}

// CombineBundles combines multiple protocol bundles into a single mega-bundle.
func CombineBundles(bundles map[string]*FullAnalysisBundle) *Bundle {
	combined := NewBundle("Combined Analysis")
	combined.Metadata["timestamp"] = fmt.Sprintf("%d", time.Now().Unix())
	combined.Metadata["num_protocols"] = fmt.Sprintf("%d", len(bundles))

	for name, bundle := range bundles {
		if bundle == nil || bundle.Bundle == nil {
			continue
		}
		combined.Metadata["protocol_"+name] = fmt.Sprintf("%v", bundle.IsSecure)
		for _, ev := range bundle.Bundle.Evidence {
			if ev != nil {
				combined.AddEvidence(ev)
			}
		}
	}

	return combined
}

// QuickAnalysis performs a quick analysis with minimal options.
func QuickAnalysis(protocolName string) (*FullAnalysisBundle, error) {
	opts := &AnalysisOptions{
		ErrorRate:       big.NewRat(0, 1),
		AdversaryModels: []string{"coherent"},
		NoiseModels:     []string{},
		IncludeAttacks:  false,
		IncludeCircuit:  false,
		Verbose:         false,
	}
	return GenerateFullAnalysis(protocolName, opts)
}

// FullAnalysis performs comprehensive analysis with all options enabled.
func FullAnalysis(protocolName string, errorRate *big.Rat) (*FullAnalysisBundle, error) {
	opts := &AnalysisOptions{
		ErrorRate:       errorRate,
		AdversaryModels: []string{"individual", "collective", "coherent"},
		NoiseModels:     []string{"depolarizing", "amplitude_damping", "phase_damping"},
		IncludeAttacks:  true,
		IncludeCircuit:  true,
		Verbose:         true,
	}
	return GenerateFullAnalysis(protocolName, opts)
}
