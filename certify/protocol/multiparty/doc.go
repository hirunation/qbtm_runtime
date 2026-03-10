// Package multiparty provides multi-party quantum protocol implementations.
//
// This package implements certified multi-party quantum protocols:
//
//   - Quantum Secret Sharing: (k,n)-threshold secret sharing
//   - Multi-party QKD: Conference key agreement
//   - Quantum Byzantine Agreement: Fault-tolerant consensus
//   - Anonymous Broadcasting: Privacy-preserving broadcast
//
// Each protocol provides:
//
//   - Complete specification as qbtm/certify/protocol.Protocol
//   - Security bounds for various adversary models
//   - Threshold parameters and fault tolerance
//   - Scalability analysis
//
// # Usage
//
//	import "qbtm/certify/protocol/multiparty"
//
//	// Get (3,5) quantum secret sharing
//	qss := multiparty.SecretSharing(3, 5)
//
//	// Get multi-party QKD for 4 parties
//	mpqkd := multiparty.ConferenceKey(4)
package multiparty
