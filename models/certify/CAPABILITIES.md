# QBTM Protocol Certifier - Capabilities and Limitations

## What the Certifier Can Verify

### Correctness Verification

The certifier can verify that a protocol implementation correctly implements its specification by:

- **Choi Matrix Comparison**: Computing the Choi-Jamiolkowski matrix of the synthesized circuit and comparing it to the ideal channel
- **Exact Equality**: Using exact rational arithmetic to verify matrix equality (no floating-point tolerance issues)
- **Fidelity Computation**: Computing the fidelity between actual and ideal implementations

**Supported**:
- Teleportation correctness (output state equals input state)
- QKD correctness (key bits match when bases match)
- Communication protocol correctness (superdense coding, swapping)

### Security Analysis

The certifier provides security bounds for:

- **Key Rate Bounds**: Exact rational lower bounds on achievable key rate
- **Security Thresholds**: Maximum tolerable QBER for positive key rate
- **Adversary Models**: Individual, collective, and coherent attacks
- **Composable Security**: Finite-key effects with security parameter epsilon

**Bounds Computed**:
| Protocol | Key Rate Formula | Threshold |
|----------|------------------|-----------|
| BB84 | `1 - 2h(e)` | 11% |
| E91 | Based on CHSH value | S > 2 |
| B92 | `(1/2)(1 - h(2e))` | 25% |
| Six-State | `1 - (5/3)h(3e/2)` | 16.67% |
| SARG04 | `1 - 2h(e) - f(mu)` | 10% |

### Attack Analysis

The certifier includes 21 attack models across four categories:

**Individual Attacks** (8 attacks):
- Intercept-Resend (random, fixed basis, Breidbart)
- Optimal Quantum Cloning (1->2, 1->N)
- Unambiguous State Discrimination (B92, SARG04)
- Phase-Covariant Cloning
- Beam Splitting

**Collective Attacks** (6 attacks):
- Optimal Collective Measurement
- Asymptotic Collective
- Symmetrization Attack
- Sequential Collective
- Post-Selection
- Shor-Preskill

**Coherent Attacks** (6 attacks):
- General Coherent (unbounded memory)
- Memory-Bounded Coherent
- Renner Security (finite-key)
- Composable Security
- Device-Independent

**Implementation Attacks** (1 category):
- Detector blinding, timing, Trojan horse, etc.

### Noise Tolerance

The certifier analyzes tolerance to:

- **Depolarizing Noise**: `Phi(rho) = (1-p)rho + p/3(XrhoX + YrhoY + ZrhoZ)`
- **Amplitude Damping**: Energy relaxation (T1 decay)
- **Phase Damping**: Dephasing (T2 decay)
- **Bit Flip**: `Phi(rho) = (1-p)rho + p*XrhoX`
- **Phase Flip**: `Phi(rho) = (1-p)rho + p*ZrhoZ`

### Protocol Composition

The certifier can analyze:

- **Sequential Composition**: Protocol A then Protocol B
- **Parallel Composition**: Protocol A alongside Protocol B
- **Security Bounds**: How security degrades under composition

---

## Exact vs Approximate Computations

### Exact (Q(i) Arithmetic)

All of the following use exact rational arithmetic:

- Security thresholds (e.g., 11/100, not 0.11)
- Key rate bounds
- Choi matrix entries
- State overlaps
- CHSH correlators
- Error rates
- Fidelity bounds

**Benefits**:
- No floating-point rounding errors
- Reproducible results
- Verifiable certificates

### Approximations Used

Some quantities require approximations:

| Quantity | Exact Value | Approximation Used |
|----------|-------------|-------------------|
| sqrt(2) | Irrational | 1414/1000 or 99/70 |
| Binary entropy h(e) | Transcendental | Rational bounds |
| sin/cos(pi/8) | Algebraic | 3827/10000, 9239/10000 |
| CHSH quantum max | 2*sqrt(2) | 2828/1000 |

**Impact**: Approximations are conservative (underestimate security when in doubt).

---

## Current Limitations

### Protocol Coverage

**Not Yet Implemented**:
- Continuous-variable QKD (CV-QKD)
- Measurement-device-independent QKD (MDI-QKD)
- Twin-field QKD
- Distributed quantum computing protocols
- Quantum money / tokens
- Quantum digital signatures

### Attack Models

**Not Modeled**:
- General side-channel attacks (beyond basic implementation attacks)
- Quantum hacking techniques with novel approaches
- Memory attacks with unbounded classical memory
- Network-level attacks in multi-party scenarios

### Analysis Depth

**Limited Analysis**:
- Finite-key effects use simplified bounds (not tight)
- Composition security is approximate
- Device imperfection modeling is simplified
- No formal proof extraction (certificates are computational, not proof-theoretic)

### Computational Constraints

- Large matrices (>100x100) may be slow
- Very high qubit counts (n>1000) not tested
- Memory usage scales with protocol complexity

---

## Attack Coverage by Protocol

| Protocol | Individual | Collective | Coherent | Implementation |
|----------|------------|------------|----------|----------------|
| BB84 | Full | Full | Full | Partial |
| E91 | Full | Full | Full | Partial |
| B92 | Full | Full | Full | Partial |
| Six-State | Full | Full | Full | Partial |
| SARG04 | Full | Full | Full | Partial |
| Teleportation | N/A | N/A | N/A | N/A |
| SuperdenseCoding | N/A | N/A | N/A | N/A |
| EntanglementSwapping | N/A | N/A | N/A | N/A |
| GHZ | Limited | Limited | Limited | N/A |
| W-State | Limited | Limited | Limited | N/A |
| SecretSharing | Limited | Limited | Limited | N/A |
| CoinFlip | N/A | N/A | N/A | N/A |
| BitCommitment | N/A | N/A | N/A | N/A |
| ObliviousTransfer | N/A | N/A | N/A | N/A |

---

## Known Gaps

### Security Proofs

- Security proofs are computational (not machine-checked formal proofs)
- Rely on correctness of implementation, not verified compiler
- Composition theorems use standard results, not re-derived

### Finite-Key Analysis

- Uses simplified Renner-style bounds
- Finite-size corrections are approximate
- Not optimal for very small key sizes (<10^4 bits)

### Device Independence

- E91 device-independent analysis is simplified
- Does not include full loophole analysis
- CHSH violation assumed to be ideal

### Multi-party Security

- GHZ/W-State security analysis is basic
- Full multi-party composition not analyzed
- Coalition attacks not fully modeled

### Implementation Attacks

The following are noted but not fully analyzed:
- Detector efficiency mismatch
- Time-shift attacks
- Phase remapping
- Wavelength-dependent attacks
- Laser damage attacks
- Electromagnetic side channels

---

## Verification Guarantees

### What is Verified

| Aspect | Guarantee |
|--------|-----------|
| Circuit synthesis | Choi matrix matches specification |
| Security bounds | Exact rational bounds |
| Attack resistance | Per-attack info-disturbance tradeoff |
| Noise tolerance | Threshold computation |

### What is Assumed

| Assumption | Description |
|------------|-------------|
| Quantum mechanics | Standard quantum formalism |
| Security definitions | Standard QKD security definitions |
| Attack models | Adversary follows modeled strategies |
| Implementation | Physical implementation matches model |

---

## Roadmap

### Planned Additions

1. **Protocols**:
   - CV-QKD (Gaussian modulation)
   - MDI-QKD
   - More cryptographic primitives

2. **Attacks**:
   - Trojan horse attack modeling
   - Memory-assisted attacks
   - Network attacks

3. **Analysis**:
   - Tighter finite-key bounds
   - Better composition analysis
   - Formal proof integration

4. **Features**:
   - Automatic countermeasure suggestions
   - Implementation checklist generation
   - Security audit reports
