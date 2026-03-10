// Package cryptographic provides quantum cryptographic primitive implementations.
//
// This package implements certified cryptographic primitives:
//
//   - Quantum Bit Commitment: Binding and hiding commitments
//   - Quantum Oblivious Transfer: 1-out-of-2 OT
//   - Quantum Coin Flipping: Fair randomness generation
//   - Quantum Digital Signatures: Unforgeable signatures
//
// Note: Some primitives (e.g., unconditionally secure bit commitment)
// are known to be impossible. This package provides:
//
//   - Bounded-storage model implementations
//   - Computational security variants
//   - Relativistic protocol variants
//
// # Usage
//
//	import "qbtm/certify/protocol/cryptographic"
//
//	// Get bounded-storage bit commitment
//	bc := cryptographic.BitCommitment(cryptographic.BoundedStorage)
//
//	// Get quantum coin flipping
//	qcf := cryptographic.CoinFlipping()
package cryptographic
