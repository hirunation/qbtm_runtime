// evidence.go provides evidence artifact types for certificates.
//
// Evidence bundles together the status, claim, and witness that
// constitute a complete proof of a security property.
package certificate

import (
	"math/big"

	"qbtm/runtime"
)

// Status represents the verification status of a claim.
type Status int

const (
	StatusUnverified Status = iota
	StatusVerified
	StatusFailed
	StatusConditional // Verified under stated assumptions
)

// String returns a human-readable name for the status.
func (s Status) String() string {
	switch s {
	case StatusUnverified:
		return "unverified"
	case StatusVerified:
		return "verified"
	case StatusFailed:
		return "failed"
	case StatusConditional:
		return "conditional"
	default:
		return "unknown"
	}
}

// Evidence represents a complete evidence artifact.
type Evidence struct {
	Status    Status
	Claim     *Claim
	Witness   *Witness
	Timestamp int64
	Version   string
}

// NewEvidence creates a new evidence artifact.
func NewEvidence(status Status, claim *Claim, witness *Witness) *Evidence {
	return &Evidence{
		Status:  status,
		Claim:   claim,
		Witness: witness,
		Version: "1.0.0",
	}
}

// IsVerified returns true if the evidence represents a verified claim.
func (e *Evidence) IsVerified() bool {
	return e.Status == StatusVerified
}

// Verify performs self-verification of the evidence.
// It checks that the witness supports the claim.
func (e *Evidence) Verify() bool {
	if e == nil {
		return false
	}

	// Already failed evidence cannot be verified
	if e.Status == StatusFailed {
		return false
	}

	// If we have a witness, verify it
	if e.Witness != nil {
		// Verify witness based on its type
		if !e.Witness.Verify() {
			return false
		}

		// Check that security bounds are positive if present
		if e.Witness.Type == WitnessSecurityBound {
			if seq, ok := e.Witness.Data.(runtime.Seq); ok && len(seq.Items) >= 2 {
				// Check key rate is non-negative
				if keyRate, ok := seq.Items[0].(runtime.Rat); ok {
					if keyRate.V.Sign() < 0 {
						return false
					}
				}
				// Check epsilon is non-negative
				if epsilon, ok := seq.Items[1].(runtime.Rat); ok {
					if epsilon.V.Sign() < 0 {
						return false
					}
				}
			}
		}
	}

	// If we have a claim, verify it has required parameters
	if e.Claim != nil {
		if !e.Claim.CanVerify() {
			return false
		}
	}

	return true
}

// ToValue converts Evidence to a runtime.Value.
func (e *Evidence) ToValue() runtime.Value {
	var claimVal runtime.Value = runtime.MakeNil()
	if e.Claim != nil {
		claimVal = e.Claim.ToValue()
	}

	var witnessVal runtime.Value = runtime.MakeNil()
	if e.Witness != nil {
		witnessVal = e.Witness.ToValue()
	}

	return runtime.MakeTag(
		runtime.MakeText("evidence"),
		runtime.MakeSeq(
			runtime.MakeInt(int64(e.Status)),
			claimVal,
			witnessVal,
			runtime.MakeInt(e.Timestamp),
			runtime.MakeText(e.Version),
		),
	)
}

// EvidenceFromValue deserializes an Evidence from a runtime.Value.
func EvidenceFromValue(v runtime.Value) (*Evidence, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "evidence" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 5 {
		return nil, false
	}

	// Parse status
	statusInt, ok := seq.Items[0].(runtime.Int)
	if !ok {
		return nil, false
	}
	status := Status(statusInt.V.Int64())

	// Parse claim
	var claim *Claim
	if _, isNil := seq.Items[1].(runtime.Nil); !isNil {
		claim, ok = ClaimFromValue(seq.Items[1])
		if !ok {
			return nil, false
		}
	}

	// Parse witness
	var witness *Witness
	if _, isNil := seq.Items[2].(runtime.Nil); !isNil {
		witness, ok = WitnessFromValue(seq.Items[2])
		if !ok {
			return nil, false
		}
	}

	// Parse timestamp
	timestamp, ok := seq.Items[3].(runtime.Int)
	if !ok {
		return nil, false
	}

	// Parse version
	version, ok := seq.Items[4].(runtime.Text)
	if !ok {
		return nil, false
	}

	return &Evidence{
		Status:    status,
		Claim:     claim,
		Witness:   witness,
		Timestamp: timestamp.V.Int64(),
		Version:   version.V,
	}, true
}

// Bundle represents a collection of evidence for a protocol.
type Bundle struct {
	ProtocolName string
	Evidence     []*Evidence
	Metadata     map[string]string
}

// NewBundle creates a new certificate bundle.
func NewBundle(protocolName string) *Bundle {
	return &Bundle{
		ProtocolName: protocolName,
		Evidence:     make([]*Evidence, 0),
		Metadata:     make(map[string]string),
	}
}

// AddEvidence adds evidence to the bundle.
func (b *Bundle) AddEvidence(e *Evidence) {
	b.Evidence = append(b.Evidence, e)
}

// AllVerified returns true if all evidence in the bundle is verified.
func (b *Bundle) AllVerified() bool {
	for _, e := range b.Evidence {
		if !e.IsVerified() {
			return false
		}
	}
	return len(b.Evidence) > 0
}

// ToValue converts a Bundle to a runtime.Value.
func (b *Bundle) ToValue() runtime.Value {
	evidence := make([]runtime.Value, len(b.Evidence))
	for i, e := range b.Evidence {
		evidence[i] = e.ToValue()
	}

	metadata := make([]runtime.Value, 0, len(b.Metadata)*2)
	for k, v := range b.Metadata {
		metadata = append(metadata, runtime.MakeText(k), runtime.MakeText(v))
	}

	return runtime.MakeTag(
		runtime.MakeText("certificate-bundle"),
		runtime.MakeSeq(
			runtime.MakeText(b.ProtocolName),
			runtime.MakeSeq(evidence...),
			runtime.MakeSeq(metadata...),
		),
	)
}

// BundleFromValue deserializes a Bundle from a runtime.Value.
func BundleFromValue(v runtime.Value) (*Bundle, bool) {
	if _, ok := v.(runtime.Nil); ok {
		return nil, true
	}

	tag, ok := v.(runtime.Tag)
	if !ok {
		return nil, false
	}
	label, ok := tag.Label.(runtime.Text)
	if !ok || label.V != "certificate-bundle" {
		return nil, false
	}
	seq, ok := tag.Payload.(runtime.Seq)
	if !ok || len(seq.Items) < 3 {
		return nil, false
	}

	// Parse protocol name
	protocolName, ok := seq.Items[0].(runtime.Text)
	if !ok {
		return nil, false
	}

	// Parse evidence list
	evidenceSeq, ok := seq.Items[1].(runtime.Seq)
	if !ok {
		return nil, false
	}
	evidence := make([]*Evidence, 0, len(evidenceSeq.Items))
	for _, item := range evidenceSeq.Items {
		ev, ok := EvidenceFromValue(item)
		if !ok {
			return nil, false
		}
		if ev != nil {
			evidence = append(evidence, ev)
		}
	}

	// Parse metadata
	metadataSeq, ok := seq.Items[2].(runtime.Seq)
	if !ok {
		return nil, false
	}
	metadata := make(map[string]string)
	for i := 0; i+1 < len(metadataSeq.Items); i += 2 {
		key, ok := metadataSeq.Items[i].(runtime.Text)
		if !ok {
			continue
		}
		val, ok := metadataSeq.Items[i+1].(runtime.Text)
		if !ok {
			continue
		}
		metadata[key.V] = val.V
	}

	return &Bundle{
		ProtocolName: protocolName.V,
		Evidence:     evidence,
		Metadata:     metadata,
	}, true
}

// VerifyAll verifies all evidence in the bundle.
func (b *Bundle) VerifyAll() bool {
	if b == nil || len(b.Evidence) == 0 {
		return false
	}
	for _, e := range b.Evidence {
		if !e.Verify() {
			return false
		}
	}
	return true
}

// ratOrNil converts a *big.Rat to Value, handling nil.
func ratOrNil(r *big.Rat) runtime.Value {
	if r == nil {
		return runtime.MakeNil()
	}
	return runtime.MakeBigRat(r)
}

// ratFromValue extracts a *big.Rat from a Value.
func ratFromValue(v runtime.Value) *big.Rat {
	if rat, ok := v.(runtime.Rat); ok {
		return new(big.Rat).Set(rat.V)
	}
	return nil
}
