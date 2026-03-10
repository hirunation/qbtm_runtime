// dispatch.go provides command dispatch for certify operations.
//
// This file implements the dispatcher that routes certify commands
// to their appropriate handlers based on the requested operation.
package certify

import (
	"fmt"
	"math/big"
	"strings"

	"qbtm/certify/analysis"
	"qbtm/certify/attack"
	"qbtm/certify/certificate"
	"qbtm/certify/protocol"
	"qbtm/runtime"
)

// Command represents a certify operation.
type Command int

const (
	CmdSynth Command = iota
	CmdVerify
	CmdSecurity
	CmdAttack
	CmdNoise
	CmdCompose
	CmdFullAnalysis
	CmdList
	CmdInfo
)

// String returns the command name.
func (c Command) String() string {
	switch c {
	case CmdSynth:
		return "synth"
	case CmdVerify:
		return "verify"
	case CmdSecurity:
		return "security"
	case CmdAttack:
		return "attack"
	case CmdNoise:
		return "noise"
	case CmdCompose:
		return "compose"
	case CmdFullAnalysis:
		return "full-analysis"
	case CmdList:
		return "list"
	case CmdInfo:
		return "info"
	default:
		return "unknown"
	}
}

// ParseCommand parses a command string into a Command.
func ParseCommand(s string) (Command, bool) {
	switch strings.ToLower(s) {
	case "synth", "synthesize", "--protocol":
		return CmdSynth, true
	case "verify", "--verify":
		return CmdVerify, true
	case "security", "--security":
		return CmdSecurity, true
	case "attack", "--attack":
		return CmdAttack, true
	case "noise", "--noise":
		return CmdNoise, true
	case "compose", "--compose":
		return CmdCompose, true
	case "full", "full-analysis", "--full-analysis":
		return CmdFullAnalysis, true
	case "list", "--list":
		return CmdList, true
	case "info", "--info":
		return CmdInfo, true
	default:
		return 0, false
	}
}

// CommandResult holds the result of a dispatched command.
type CommandResult struct {
	Success bool
	Message string
	Data    interface{}
	Value   runtime.Value // Runtime value for serialization
}

// DispatchOptions contains options for command execution.
type DispatchOptions struct {
	ErrorRate      *big.Rat
	AdversaryModel string
	NoiseModel     string
	Verbose        bool
	OutputFormat   string // "text", "json", "value"
}

// DefaultDispatchOptions returns default dispatch options.
func DefaultDispatchOptions() *DispatchOptions {
	return &DispatchOptions{
		ErrorRate:      big.NewRat(0, 1),
		AdversaryModel: "coherent",
		NoiseModel:     "depolarizing",
		Verbose:        false,
		OutputFormat:   "text",
	}
}

// Dispatch routes a command to its handler.
func Dispatch(cmd Command, args []string) (*CommandResult, error) {
	return DispatchWithOptions(cmd, args, DefaultDispatchOptions())
}

// DispatchWithOptions routes a command with options.
func DispatchWithOptions(cmd Command, args []string, opts *DispatchOptions) (*CommandResult, error) {
	if opts == nil {
		opts = DefaultDispatchOptions()
	}

	switch cmd {
	case CmdSynth:
		return dispatchSynth(args, opts)
	case CmdVerify:
		return dispatchVerify(args, opts)
	case CmdSecurity:
		return dispatchSecurity(args, opts)
	case CmdAttack:
		return dispatchAttack(args, opts)
	case CmdNoise:
		return dispatchNoise(args, opts)
	case CmdCompose:
		return dispatchCompose(args, opts)
	case CmdFullAnalysis:
		return dispatchFullAnalysis(args, opts)
	case CmdList:
		return dispatchList(args, opts)
	case CmdInfo:
		return dispatchInfo(args, opts)
	default:
		return nil, fmt.Errorf("unknown command: %d", cmd)
	}
}

// dispatchSynth handles protocol synthesis.
func dispatchSynth(args []string, opts *DispatchOptions) (*CommandResult, error) {
	if len(args) == 0 {
		return &CommandResult{
			Success: false,
			Message: "synth: protocol name required",
		}, fmt.Errorf("protocol name required")
	}

	protocolName := args[0]

	// Get the protocol synthesizer
	synth, err := certificate.GetProtocol(protocolName)
	if err != nil {
		return &CommandResult{
			Success: false,
			Message: fmt.Sprintf("synth: %v", err),
		}, err
	}

	// Create store and synthesize
	store := runtime.NewStore()
	qgid, err := synth.Synthesize(store)
	if err != nil {
		return &CommandResult{
			Success: false,
			Message: fmt.Sprintf("synth: failed to synthesize %s: %v", protocolName, err),
		}, err
	}

	// Get the synthesized circuit value
	var circuitVal runtime.Value = runtime.MakeNil()
	if val, ok := store.GetValue(qgid); ok {
		circuitVal = val
	}

	message := fmt.Sprintf("Synthesized protocol: %s\nQGID: %x\n", protocolName, qgid)

	return &CommandResult{
		Success: true,
		Message: message,
		Data: map[string]interface{}{
			"protocol": protocolName,
			"qgid":     qgid,
			"store":    store,
		},
		Value: circuitVal,
	}, nil
}

// dispatchVerify handles correctness verification.
func dispatchVerify(args []string, opts *DispatchOptions) (*CommandResult, error) {
	if len(args) == 0 {
		return &CommandResult{
			Success: false,
			Message: "verify: protocol name required",
		}, fmt.Errorf("protocol name required")
	}

	protocolName := args[0]

	// Get the protocol synthesizer
	synth, err := certificate.GetProtocol(protocolName)
	if err != nil {
		return &CommandResult{
			Success: false,
			Message: fmt.Sprintf("verify: %v", err),
		}, err
	}

	proto := synth.Protocol()
	if proto == nil {
		return &CommandResult{
			Success: false,
			Message: "verify: protocol specification is nil",
		}, fmt.Errorf("protocol specification is nil")
	}

	// Create store and verify
	store := runtime.NewStore()
	result, err := analysis.VerifyCorrectness(proto, store)
	if err != nil {
		return &CommandResult{
			Success: false,
			Message: fmt.Sprintf("verify: failed to verify %s: %v", protocolName, err),
		}, err
	}

	// Build message
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Correctness Verification: %s\n", protocolName))
	sb.WriteString(fmt.Sprintf("==============================\n"))
	if result.Correct {
		sb.WriteString("Status: CORRECT\n")
	} else {
		sb.WriteString("Status: INCORRECT\n")
		if result.ErrorMessage != "" {
			sb.WriteString(fmt.Sprintf("Error: %s\n", result.ErrorMessage))
		}
	}
	if result.Fidelity != nil {
		sb.WriteString(fmt.Sprintf("Fidelity: %s\n", result.Fidelity.RatString()))
	}

	// Create evidence
	evidence := certificate.CreateFromCorrectnessResult(
		result.Correct,
		result.Fidelity,
		result.ChoiMatrix,
		result.IdealChannel,
	)

	return &CommandResult{
		Success: result.Correct,
		Message: sb.String(),
		Data: map[string]interface{}{
			"protocol":   protocolName,
			"correct":    result.Correct,
			"fidelity":   result.Fidelity,
			"choiMatrix": result.ChoiMatrix,
			"ideal":      result.IdealChannel,
		},
		Value: evidence.ToValue(),
	}, nil
}

// dispatchSecurity handles security analysis.
func dispatchSecurity(args []string, opts *DispatchOptions) (*CommandResult, error) {
	if len(args) == 0 {
		return &CommandResult{
			Success: false,
			Message: "security: protocol name required",
		}, fmt.Errorf("protocol name required")
	}

	protocolName := args[0]

	// Get the protocol synthesizer
	synth, err := certificate.GetProtocol(protocolName)
	if err != nil {
		return &CommandResult{
			Success: false,
			Message: fmt.Sprintf("security: %v", err),
		}, err
	}

	proto := synth.Protocol()
	if proto == nil {
		return &CommandResult{
			Success: false,
			Message: "security: protocol specification is nil",
		}, fmt.Errorf("protocol specification is nil")
	}

	// Compute security bounds
	result, err := analysis.ComputeSecurityBounds(proto, opts.AdversaryModel)
	if err != nil {
		return &CommandResult{
			Success: false,
			Message: fmt.Sprintf("security: analysis failed: %v", err),
		}, err
	}

	// Build message
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Security Analysis: %s\n", protocolName))
	sb.WriteString(fmt.Sprintf("============================\n"))
	sb.WriteString(fmt.Sprintf("Adversary Model: %s\n", opts.AdversaryModel))
	if result.IsSecure {
		sb.WriteString("Status: SECURE\n")
	} else {
		sb.WriteString("Status: INSECURE\n")
	}
	if result.Threshold != nil {
		sb.WriteString(fmt.Sprintf("Security Threshold: %s\n", result.Threshold.RatString()))
	}
	if result.KeyRate != nil {
		sb.WriteString(fmt.Sprintf("Key Rate: %s\n", result.KeyRate.String()))
	}
	if result.KeyRateBound != nil {
		sb.WriteString(fmt.Sprintf("Key Rate Bound: %s\n", result.KeyRateBound.RatString()))
	}
	sb.WriteString(fmt.Sprintf("\n%s\n", analysis.ThresholdDerivation(protocolName)))

	// Create evidence
	evidence := certificate.CreateFromSecurityResult(
		protocolName,
		opts.AdversaryModel,
		result.KeyRateBound,
		result.Threshold,
		result.IsSecure,
	)

	return &CommandResult{
		Success: result.IsSecure,
		Message: sb.String(),
		Data: map[string]interface{}{
			"protocol":   protocolName,
			"model":      opts.AdversaryModel,
			"secure":     result.IsSecure,
			"threshold":  result.Threshold,
			"keyRate":    result.KeyRate,
			"keyRateBound": result.KeyRateBound,
		},
		Value: evidence.ToValue(),
	}, nil
}

// dispatchAttack handles attack simulation.
func dispatchAttack(args []string, opts *DispatchOptions) (*CommandResult, error) {
	if len(args) == 0 {
		return &CommandResult{
			Success: false,
			Message: "attack: protocol name required",
		}, fmt.Errorf("protocol name required")
	}

	protocolName := args[0]

	// Get applicable attacks
	attacks := attack.AttacksForProtocol(protocolName)
	if len(attacks) == 0 {
		return &CommandResult{
			Success: true,
			Message: fmt.Sprintf("No known attacks for protocol: %s\n", protocolName),
			Data:    nil,
		}, nil
	}

	// Build message
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Attack Analysis: %s\n", protocolName))
	sb.WriteString(fmt.Sprintf("==========================\n"))
	sb.WriteString(fmt.Sprintf("Applicable attacks: %d\n\n", len(attacks)))

	evidenceList := make([]*certificate.Evidence, 0, len(attacks))

	for _, atk := range attacks {
		sb.WriteString(fmt.Sprintf("Attack: %s\n", atk.Name()))
		sb.WriteString(fmt.Sprintf("  Description: %s\n", atk.Description()))
		sb.WriteString(fmt.Sprintf("  Information Gained: %s\n", atk.InformationGained().RatString()))
		sb.WriteString(fmt.Sprintf("  Disturbance Induced: %s\n", atk.DisturbanceInduced().RatString()))

		detectable := atk.DisturbanceInduced().Sign() > 0
		if detectable {
			sb.WriteString("  Detectability: DETECTABLE\n")
		} else {
			sb.WriteString("  Detectability: UNDETECTABLE\n")
		}
		sb.WriteString("\n")

		// Create evidence
		ev := certificate.CreateFromAttackAnalysis(
			protocolName,
			atk.Name(),
			atk.InformationGained(),
			atk.DisturbanceInduced(),
			detectable,
		)
		evidenceList = append(evidenceList, ev)
	}

	// Create bundle value
	bundle := certificate.NewBundle(protocolName)
	bundle.Metadata["analysis_type"] = "attack"
	for _, ev := range evidenceList {
		bundle.AddEvidence(ev)
	}

	return &CommandResult{
		Success: true,
		Message: sb.String(),
		Data: map[string]interface{}{
			"protocol": protocolName,
			"attacks":  attacks,
			"count":    len(attacks),
		},
		Value: bundle.ToValue(),
	}, nil
}

// dispatchNoise handles noise tolerance analysis.
func dispatchNoise(args []string, opts *DispatchOptions) (*CommandResult, error) {
	if len(args) == 0 {
		return &CommandResult{
			Success: false,
			Message: "noise: protocol name required",
		}, fmt.Errorf("protocol name required")
	}

	protocolName := args[0]

	// Get the protocol synthesizer
	synth, err := certificate.GetProtocol(protocolName)
	if err != nil {
		return &CommandResult{
			Success: false,
			Message: fmt.Sprintf("noise: %v", err),
		}, err
	}

	proto := synth.Protocol()
	if proto == nil {
		return &CommandResult{
			Success: false,
			Message: "noise: protocol specification is nil",
		}, fmt.Errorf("protocol specification is nil")
	}

	// Create noise model
	var noiseModel *analysis.NoiseModel
	switch opts.NoiseModel {
	case "depolarizing":
		noiseModel = analysis.Depolarizing(opts.ErrorRate)
	case "amplitude_damping", "amplitude-damping":
		noiseModel = analysis.AmplitudeDamping(opts.ErrorRate)
	case "dephasing", "phase_damping", "phase-damping":
		noiseModel = analysis.Dephasing(opts.ErrorRate)
	default:
		noiseModel = analysis.Depolarizing(opts.ErrorRate)
	}

	// Analyze noise tolerance
	result, err := analysis.AnalyzeNoiseTolerance(proto, noiseModel)
	if err != nil {
		return &CommandResult{
			Success: false,
			Message: fmt.Sprintf("noise: analysis failed: %v", err),
		}, err
	}

	// Get thresholds
	thresholds := analysis.ComputeNoiseThresholds(protocolName)

	// Build message
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Noise Tolerance Analysis: %s\n", protocolName))
	sb.WriteString(fmt.Sprintf("================================\n"))
	sb.WriteString(fmt.Sprintf("Noise Model: %s\n", opts.NoiseModel))
	sb.WriteString(fmt.Sprintf("Error Rate: %s\n", opts.ErrorRate.RatString()))
	if result.Tolerant {
		sb.WriteString("Status: TOLERANT\n")
	} else {
		sb.WriteString("Status: INTOLERANT\n")
	}
	if result.MaxNoise != nil {
		sb.WriteString(fmt.Sprintf("Maximum Tolerable Noise: %s\n", result.MaxNoise.RatString()))
	}
	if result.SecurityAtNoise != nil {
		sb.WriteString(fmt.Sprintf("Key Rate at Noise: %s\n", result.SecurityAtNoise.RatString()))
	}
	if result.BreakpointNoise != nil {
		sb.WriteString(fmt.Sprintf("Security Breakpoint: %s\n", result.BreakpointNoise.RatString()))
	}
	sb.WriteString("\nNoise Thresholds:\n")
	if thresholds.Depolarizing != nil {
		sb.WriteString(fmt.Sprintf("  Depolarizing: %s\n", thresholds.Depolarizing.RatString()))
	}
	if thresholds.AmplitudeDamping != nil {
		sb.WriteString(fmt.Sprintf("  Amplitude Damping: %s\n", thresholds.AmplitudeDamping.RatString()))
	}
	if thresholds.PhaseDamping != nil {
		sb.WriteString(fmt.Sprintf("  Phase Damping: %s\n", thresholds.PhaseDamping.RatString()))
	}

	// Create evidence
	threshold := analysis.GetSecurityThreshold(protocolName)
	margin := new(big.Rat).Sub(result.MaxNoise, opts.ErrorRate)
	evidence := certificate.CreateFromNoiseResult(
		protocolName,
		opts.ErrorRate,
		threshold,
		result.Tolerant,
		margin,
		opts.NoiseModel,
	)

	return &CommandResult{
		Success: result.Tolerant,
		Message: sb.String(),
		Data: map[string]interface{}{
			"protocol":   protocolName,
			"noiseModel": opts.NoiseModel,
			"tolerant":   result.Tolerant,
			"maxNoise":   result.MaxNoise,
			"thresholds": thresholds,
		},
		Value: evidence.ToValue(),
	}, nil
}

// dispatchCompose handles protocol composition.
func dispatchCompose(args []string, opts *DispatchOptions) (*CommandResult, error) {
	if len(args) < 2 {
		return &CommandResult{
			Success: false,
			Message: "compose: at least two protocol names required",
		}, fmt.Errorf("at least two protocol names required")
	}

	// Get protocols
	protocols := make([]*protocol.Protocol, len(args))
	for i, name := range args {
		synth, err := certificate.GetProtocol(name)
		if err != nil {
			return &CommandResult{
				Success: false,
				Message: fmt.Sprintf("compose: failed to get protocol %s: %v", name, err),
			}, err
		}
		protocols[i] = synth.Protocol()
		if protocols[i] == nil {
			return &CommandResult{
				Success: false,
				Message: fmt.Sprintf("compose: protocol %s has nil specification", name),
			}, fmt.Errorf("protocol %s has nil specification", name)
		}
	}

	// Compose sequentially
	result, err := analysis.AnalyzeComposition(protocols, analysis.SequentialComposition)
	if err != nil {
		return &CommandResult{
			Success: false,
			Message: fmt.Sprintf("compose: failed to compose protocols: %v", err),
		}, err
	}

	// Build message
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Protocol Composition Analysis\n"))
	sb.WriteString(fmt.Sprintf("==============================\n"))
	sb.WriteString(fmt.Sprintf("Base Protocols: %v\n", result.BaseProtocols))
	sb.WriteString(fmt.Sprintf("Composed Name: %s\n", result.ComposedName))
	if result.Composable {
		sb.WriteString("Status: COMPOSABLE\n")
	} else {
		sb.WriteString("Status: NOT COMPOSABLE\n")
	}
	if result.SecurityBound != nil {
		sb.WriteString(fmt.Sprintf("Security Bound: %s\n", result.SecurityBound.String()))
	}
	if result.Certificate != nil {
		sb.WriteString(fmt.Sprintf("\nComposition Proof:\n%s\n", result.Certificate.CompositionProof))
	}

	return &CommandResult{
		Success: result.Composable,
		Message: sb.String(),
		Data: map[string]interface{}{
			"baseProtocols": result.BaseProtocols,
			"composedName":  result.ComposedName,
			"composable":    result.Composable,
			"securityBound": result.SecurityBound,
		},
		Value: result.ToValue(),
	}, nil
}

// dispatchFullAnalysis handles comprehensive protocol analysis.
func dispatchFullAnalysis(args []string, opts *DispatchOptions) (*CommandResult, error) {
	if len(args) == 0 {
		return &CommandResult{
			Success: false,
			Message: "full-analysis: protocol name required",
		}, fmt.Errorf("protocol name required")
	}

	protocolName := args[0]

	// Build analysis options
	analysisOpts := &certificate.AnalysisOptions{
		ErrorRate:       opts.ErrorRate,
		AdversaryModels: []string{"individual", "collective", "coherent"},
		NoiseModels:     []string{"depolarizing", "amplitude_damping", "phase_damping"},
		IncludeAttacks:  true,
		IncludeCircuit:  true,
		Verbose:         opts.Verbose,
	}

	// If a specific adversary model is requested, use only that one
	if opts.AdversaryModel != "" && opts.AdversaryModel != "coherent" {
		analysisOpts.AdversaryModels = []string{opts.AdversaryModel}
	}

	// Generate full analysis
	bundle, err := certificate.GenerateFullAnalysis(protocolName, analysisOpts)
	if err != nil {
		return &CommandResult{
			Success: false,
			Message: fmt.Sprintf("full-analysis: failed to analyze %s: %v", protocolName, err),
		}, err
	}

	// Generate summary
	summary := bundle.GenerateSummary()

	return &CommandResult{
		Success: bundle.IsSecure,
		Message: summary,
		Data: map[string]interface{}{
			"protocol":  protocolName,
			"bundle":    bundle,
			"secure":    bundle.IsSecure,
			"threshold": bundle.SecurityThreshold,
			"keyRate":   bundle.KeyRate,
		},
		Value: bundle.ToValue(),
	}, nil
}

// dispatchList lists all registered protocols.
func dispatchList(args []string, opts *DispatchOptions) (*CommandResult, error) {
	protocols := certificate.RegisteredProtocols()

	var sb strings.Builder
	sb.WriteString("Registered Protocols\n")
	sb.WriteString("====================\n\n")

	// Group by category
	categories := map[string][]string{
		"QKD":           {},
		"Communication": {},
		"Multiparty":    {},
		"Cryptographic": {},
	}

	for _, name := range protocols {
		info := certificate.ProtocolInfo(name)
		if info != nil {
			categories[info.Category] = append(categories[info.Category], name)
		}
	}

	for category, protos := range categories {
		if len(protos) > 0 {
			sb.WriteString(fmt.Sprintf("%s:\n", category))
			for _, name := range protos {
				info := certificate.ProtocolInfo(name)
				if info != nil {
					sb.WriteString(fmt.Sprintf("  - %s: %s\n", name, info.Description))
				} else {
					sb.WriteString(fmt.Sprintf("  - %s\n", name))
				}
			}
			sb.WriteString("\n")
		}
	}

	// Create value
	protoVals := make([]runtime.Value, len(protocols))
	for i, name := range protocols {
		protoVals[i] = runtime.MakeText(name)
	}

	return &CommandResult{
		Success: true,
		Message: sb.String(),
		Data: map[string]interface{}{
			"protocols": protocols,
			"count":     len(protocols),
		},
		Value: runtime.MakeSeq(protoVals...),
	}, nil
}

// dispatchInfo shows detailed information about a protocol.
func dispatchInfo(args []string, opts *DispatchOptions) (*CommandResult, error) {
	if len(args) == 0 {
		return &CommandResult{
			Success: false,
			Message: "info: protocol name required",
		}, fmt.Errorf("protocol name required")
	}

	protocolName := args[0]
	info := certificate.ProtocolInfo(protocolName)
	if info == nil {
		return &CommandResult{
			Success: false,
			Message: fmt.Sprintf("info: unknown protocol: %s", protocolName),
		}, fmt.Errorf("unknown protocol: %s", protocolName)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Protocol Information: %s\n", info.Name))
	sb.WriteString(fmt.Sprintf("==============================\n\n"))
	sb.WriteString(fmt.Sprintf("Category: %s\n", info.Category))
	sb.WriteString(fmt.Sprintf("Description: %s\n", info.Description))
	sb.WriteString(fmt.Sprintf("Security Goal: %s\n", info.SecurityGoal))
	if info.Threshold != nil {
		sb.WriteString(fmt.Sprintf("Security Threshold: %s\n", info.Threshold.RatString()))
	}
	if info.KeyRateFormula != "" {
		sb.WriteString(fmt.Sprintf("Key Rate Formula: %s\n", info.KeyRateFormula))
	}
	if info.DefaultNumBits > 0 {
		sb.WriteString(fmt.Sprintf("Default Key Length: %d bits\n", info.DefaultNumBits))
	}
	if len(info.Assumptions) > 0 {
		sb.WriteString("\nAssumptions:\n")
		for _, a := range info.Assumptions {
			sb.WriteString(fmt.Sprintf("  - %s\n", a))
		}
	}

	// Create value
	var thresholdVal runtime.Value = runtime.MakeNil()
	if info.Threshold != nil {
		thresholdVal = runtime.MakeBigRat(info.Threshold)
	}

	assumptions := make([]runtime.Value, len(info.Assumptions))
	for i, a := range info.Assumptions {
		assumptions[i] = runtime.MakeText(a)
	}

	infoVal := runtime.MakeTag(
		runtime.MakeText("protocol-info"),
		runtime.MakeSeq(
			runtime.MakeText(info.Name),
			runtime.MakeText(info.Category),
			runtime.MakeText(info.Description),
			runtime.MakeText(info.SecurityGoal),
			thresholdVal,
			runtime.MakeText(info.KeyRateFormula),
			runtime.MakeInt(int64(info.DefaultNumBits)),
			runtime.MakeSeq(assumptions...),
		),
	)

	return &CommandResult{
		Success: true,
		Message: sb.String(),
		Data: map[string]interface{}{
			"info": info,
		},
		Value: infoVal,
	}, nil
}

// FullAnalysis runs complete protocol analysis.
// This is the main entry point for comprehensive certification.
func FullAnalysis(protocolName string, options map[string]interface{}) (*CommandResult, error) {
	opts := DefaultDispatchOptions()

	// Parse options
	if options != nil {
		if errorRate, ok := options["error_rate"].(*big.Rat); ok {
			opts.ErrorRate = errorRate
		}
		if model, ok := options["adversary_model"].(string); ok {
			opts.AdversaryModel = model
		}
		if noiseModel, ok := options["noise_model"].(string); ok {
			opts.NoiseModel = noiseModel
		}
		if verbose, ok := options["verbose"].(bool); ok {
			opts.Verbose = verbose
		}
	}

	return DispatchWithOptions(CmdFullAnalysis, []string{protocolName}, opts)
}

// QuickVerify performs quick correctness verification.
func QuickVerify(protocolName string) (*CommandResult, error) {
	return Dispatch(CmdVerify, []string{protocolName})
}

// AnalyzeSecurity performs security analysis with specified adversary model.
func AnalyzeSecurity(protocolName, adversaryModel string, errorRate *big.Rat) (*CommandResult, error) {
	opts := &DispatchOptions{
		ErrorRate:      errorRate,
		AdversaryModel: adversaryModel,
		Verbose:        true,
	}
	return DispatchWithOptions(CmdSecurity, []string{protocolName}, opts)
}

// ListProtocols returns all registered protocols.
func ListProtocols() (*CommandResult, error) {
	return Dispatch(CmdList, nil)
}

// GetProtocolInfo returns information about a protocol.
func GetProtocolInfo(protocolName string) (*CommandResult, error) {
	return Dispatch(CmdInfo, []string{protocolName})
}
