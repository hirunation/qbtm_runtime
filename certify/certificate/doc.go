// Package certificate provides certificate generation for protocol proofs.
//
// Certificates are structured evidence artifacts that prove security properties:
//
//   - Evidence: Status, Claim, Witness tuple
//   - Witnesses: Computational artifacts (Choi matrices, bounds, etc.)
//   - Claims: Security assertions (correctness, security, composition)
//
// All certificates can be serialized to runtime.Value for embedding in .qmb files.
package certificate
