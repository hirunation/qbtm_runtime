// Package certify provides quantum protocol certification and security analysis.
//
// The certify package synthesizes, verifies, and certifies quantum communication
// protocols with exact security bounds over the Gaussian rationals Q(i).
//
// Core thesis: Security proofs as executable artifacts, not paper claims.
//
// # Architecture
//
// The package is organized into subpackages:
//
//   - protocol: Protocol definitions (QKD, communication, multiparty, cryptographic)
//   - attack: Attack library (individual, collective, coherent, implementation)
//   - analysis: Analysis engine (correctness, security, noise, entropy, composition)
//   - certificate: Certificate generation (evidence, witnesses, claims)
//
// # Usage
//
// Use the cmd/certify CLI or import the package directly:
//
//	import "qbtm/certify"
//
//	// Analyze a protocol
//	result, err := certify.FullAnalysis("BB84", nil)
//
// # Exact Arithmetic
//
// All computations use exact rational arithmetic via Q(i) (Gaussian rationals).
// No floating-point approximations are used in security bound calculations.
package certify
