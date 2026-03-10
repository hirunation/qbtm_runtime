// cmd/certify provides the CLI for QBTM protocol certification.
//
// Usage:
//
//	certify <command> [options] [protocol]
//
// Commands:
//
//	synth          Synthesize protocol model
//	verify         Verify protocol correctness
//	security       Compute security bounds
//	attack         Analyze attack resistance
//	noise          Analyze noise tolerance
//	compose        Compose protocols
//	full-analysis  Run complete certification
//	list           List available protocols
//	info           Show protocol information
//
// Examples:
//
//	certify synth BB84
//	certify security --attack=coherent BB84
//	certify full-analysis --output=cert.qmb BB84
package main

import (
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"qbtm/certify"
)

const (
	version = "1.0.0"
	usage   = `certify - QBTM Protocol Certification Tool

Usage:
  certify <command> [options] [protocol]

Commands:
  synth          Synthesize protocol model from specification
  verify         Verify protocol correctness via Choi matrix
  security       Compute security bounds (key rate, epsilon)
  attack         Analyze resistance to specified attack model
  noise          Analyze noise tolerance thresholds
  compose        Compose multiple protocols
  full-analysis  Run complete certification pipeline
  list           List all available protocols
  info           Show detailed protocol information

Options:
  -h, --help        Show this help message
  -v, --version     Show version information
  -o, --output      Output file path (default: stdout)
  --attack          Attack model: individual, collective, coherent (default: coherent)
  --noise           Noise model: depolarizing, amplitude_damping, phase_damping
  --format          Output format: text, json, qmb (default: text)
  --error-rate      QBER for analysis (e.g., "1/100" for 1%)
  --self-verify     Verify correctness before emitting (default: true)
  --verbose         Include detailed derivations

Examples:
  certify synth BB84
  certify verify BB84
  certify security --attack=coherent BB84
  certify noise --noise=depolarizing BB84
  certify compose BB84 Teleportation
  certify full-analysis --output=bb84_cert.qmb BB84
  certify list
  certify info BB84

Supported Protocols:
  QKD:            BB84, E91, B92, Six-State, SARG04
  Communication:  Teleportation, SuperdenseCoding, EntanglementSwapping
  Multi-party:    GHZ, W-State, SecretSharing
  Cryptographic:  CoinFlip, BitCommitment, ObliviousTransfer
`
)

func main() {
	// Global flags
	helpFlag := flag.Bool("help", false, "Show help message")
	hFlag := flag.Bool("h", false, "Show help message")
	versionFlag := flag.Bool("version", false, "Show version")
	vFlag := flag.Bool("v", false, "Show version")
	outputFlag := flag.String("output", "", "Output file path")
	oFlag := flag.String("o", "", "Output file path")
	attackFlag := flag.String("attack", "coherent", "Attack model")
	noiseFlag := flag.String("noise", "depolarizing", "Noise model")
	formatFlag := flag.String("format", "text", "Output format")
	errorRateFlag := flag.String("error-rate", "0", "QBER for analysis (e.g., '1/100')")
	selfVerifyFlag := flag.Bool("self-verify", true, "Verify correctness before emitting")
	verboseFlag := flag.Bool("verbose", false, "Include detailed derivations")

	flag.Usage = func() {
		fmt.Print(usage)
	}

	flag.Parse()

	// Handle help
	if *helpFlag || *hFlag {
		fmt.Print(usage)
		os.Exit(0)
	}

	// Handle version
	if *versionFlag || *vFlag {
		fmt.Printf("certify version %s\n", version)
		os.Exit(0)
	}

	// Get command and arguments
	args := flag.Args()
	if len(args) < 1 {
		fmt.Print(usage)
		os.Exit(1)
	}

	command := args[0]
	cmdArgs := args[1:]

	// Resolve output path
	output := *outputFlag
	if output == "" {
		output = *oFlag
	}

	// Parse error rate
	errorRate := big.NewRat(0, 1)
	if *errorRateFlag != "" && *errorRateFlag != "0" {
		if strings.Contains(*errorRateFlag, "/") {
			parts := strings.Split(*errorRateFlag, "/")
			if len(parts) == 2 {
				num, ok1 := new(big.Int).SetString(parts[0], 10)
				den, ok2 := new(big.Int).SetString(parts[1], 10)
				if ok1 && ok2 && den.Sign() != 0 {
					errorRate = new(big.Rat).SetFrac(num, den)
				}
			}
		} else {
			// Try parsing as decimal
			if r, ok := new(big.Rat).SetString(*errorRateFlag); ok {
				errorRate = r
			}
		}
	}

	// Parse format
	format, _ := certify.ParseOutputFormat(*formatFlag)

	// Create dispatch options
	opts := &certify.DispatchOptions{
		ErrorRate:      errorRate,
		AdversaryModel: *attackFlag,
		NoiseModel:     *noiseFlag,
		Verbose:        *verboseFlag,
		OutputFormat:   *formatFlag,
	}

	// Dispatch command
	var err error
	var result *certify.CommandResult

	switch command {
	case "synth":
		result, err = certify.DispatchWithOptions(certify.CmdSynth, cmdArgs, opts)
	case "verify":
		result, err = certify.DispatchWithOptions(certify.CmdVerify, cmdArgs, opts)
	case "security":
		result, err = certify.DispatchWithOptions(certify.CmdSecurity, cmdArgs, opts)
	case "attack":
		result, err = certify.DispatchWithOptions(certify.CmdAttack, cmdArgs, opts)
	case "noise":
		result, err = certify.DispatchWithOptions(certify.CmdNoise, cmdArgs, opts)
	case "compose":
		result, err = certify.DispatchWithOptions(certify.CmdCompose, cmdArgs, opts)
	case "full-analysis":
		err = cmdFullAnalysis(cmdArgs, output, *attackFlag, *noiseFlag, *formatFlag, errorRate, *selfVerifyFlag, *verboseFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	case "list":
		result, err = certify.DispatchWithOptions(certify.CmdList, cmdArgs, opts)
	case "info":
		result, err = certify.DispatchWithOptions(certify.CmdInfo, cmdArgs, opts)
	case "emit":
		err = cmdEmit(cmdArgs, output, format, *selfVerifyFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		fmt.Print(usage)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Emit result
	if result != nil {
		err = certify.EmitCommandResult(result, output, format)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error emitting result: %v\n", err)
			os.Exit(1)
		}
	}

	// Set exit code based on result success
	if result != nil && !result.Success {
		os.Exit(1)
	}
}

// cmdFullAnalysis runs the complete certification pipeline.
func cmdFullAnalysis(args []string, output, attack, noise, formatStr string, errorRate *big.Rat, selfVerify, verbose bool) error {
	if len(args) < 1 {
		return fmt.Errorf("full-analysis requires a protocol name")
	}
	protocolName := args[0]

	// Create options
	opts := &certify.DispatchOptions{
		ErrorRate:      errorRate,
		AdversaryModel: attack,
		NoiseModel:     noise,
		Verbose:        verbose,
	}

	// Run full analysis
	result, err := certify.DispatchWithOptions(certify.CmdFullAnalysis, []string{protocolName}, opts)
	if err != nil {
		return err
	}

	// Parse format
	format, _ := certify.ParseOutputFormat(formatStr)

	// If output is specified and format is qmb, emit as .qmb file
	if output != "" && format == certify.FormatQMB {
		emitOpts := &certify.EmitOptions{
			Format:             format,
			ComputeChoi:        true,
			SelfVerify:         selfVerify,
			StrictVerify:       false,
			IncludeCertificate: true,
			IncludeSecurity:    true,
			IncludeNoise:       true,
			IncludeAttacks:     true,
			Verbose:            verbose,
			ErrorRate:          errorRate,
			AdversaryModel:     attack,
			NoiseModels:        []string{noise, "amplitude_damping", "phase_damping"},
		}
		return certify.EmitModel(protocolName, output, emitOpts)
	}

	// Otherwise emit the command result
	return certify.EmitCommandResult(result, output, format)
}

// cmdEmit emits a certified model to a file.
func cmdEmit(args []string, output string, format certify.OutputFormat, selfVerify bool) error {
	if len(args) < 1 {
		return fmt.Errorf("emit requires a protocol name")
	}
	protocolName := args[0]

	if output == "" {
		output = protocolName + ".qmb"
	}

	opts := &certify.EmitOptions{
		Format:             format,
		ComputeChoi:        true,
		SelfVerify:         selfVerify,
		StrictVerify:       false,
		IncludeCertificate: true,
		IncludeSecurity:    false,
		IncludeNoise:       false,
		IncludeAttacks:     false,
		Verbose:            false,
		ErrorRate:          nil,
		AdversaryModel:     "coherent",
		NoiseModels:        []string{"depolarizing"},
	}

	err := certify.EmitModel(protocolName, output, opts)
	if err != nil {
		return err
	}

	fmt.Printf("Emitted certified model to: %s\n", output)
	return nil
}
