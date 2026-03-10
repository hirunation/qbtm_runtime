# QBTM Protocol Certifier - Technical Specification

## Architecture Overview

The certifier is organized into four major subsystems:

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI / Dispatcher                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │   Protocol    │  │    Attack     │  │   Analysis    │       │
│  │  Definitions  │  │    Library    │  │    Engine     │       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
│         │                   │                   │               │
│         └───────────────────┼───────────────────┘               │
│                             │                                   │
│                    ┌────────────────┐                           │
│                    │  Certificate   │                           │
│                    │   Generator    │                           │
│                    └────────────────┘                           │
│                             │                                   │
│                    ┌────────────────┐                           │
│                    │   .qmb Emit    │                           │
│                    └────────────────┘                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Type System: Q(i) Arithmetic

All security computations use exact rational arithmetic over Q(i), the Gaussian rationals.

### Gaussian Rationals

A Gaussian rational is a complex number of the form:

```
z = a + bi where a, b in Q (rationals)
```

Represented as:

```go
type QI struct {
    Re *big.Rat  // Real part
    Im *big.Rat  // Imaginary part
}
```

### Operations

| Operation | Definition |
|-----------|------------|
| Addition | `(a+bi) + (c+di) = (a+c) + (b+d)i` |
| Multiplication | `(a+bi) * (c+di) = (ac-bd) + (ad+bc)i` |
| Conjugate | `conj(a+bi) = a - bi` |
| Magnitude | `|a+bi|^2 = a^2 + b^2` (rational) |

### Matrix Representation

Quantum states and channels use matrices over Q(i):

```go
type Matrix struct {
    Rows, Cols int
    Data       []QI  // Row-major order
}
```

## Protocol Specification Language

### Protocol Structure

```go
type Protocol struct {
    Name        string           // Protocol identifier
    Description string           // Human-readable description
    Parties     []Party          // Participants
    Resources   []Resource       // Quantum/classical resources
    Rounds      []Round          // Protocol steps
    Goal        SecurityGoal     // Security objective
    Assumptions []Assumption     // Security assumptions
    TypeSig     TypeSignature    // Quantum type signature
}
```

### Party Roles

| Role | Description |
|------|-------------|
| `Sender` | Initiates transmission |
| `Receiver` | Receives transmission |
| `Adversary` | Malicious party (for analysis) |
| `Arbiter` | Trusted third party (e.g., entanglement source) |

### Capabilities

| Capability | Description |
|------------|-------------|
| `Prepare` | Prepare quantum states |
| `Measure` | Measure quantum states |
| `Store` | Store quantum states |
| `ClassicalCommunicate` | Classical channel access |
| `QuantumCommunicate` | Quantum channel access |

### Resource Types

| Resource | Description |
|----------|-------------|
| `ClassicalChannel` | Classical communication |
| `QuantumChannel` | Quantum communication |
| `EntangledPair` | Pre-shared entanglement |
| `SharedRandomness` | Common randomness |
| `AuthenticatedChannel` | Authenticated classical channel |

### Action Types

| Action | Description |
|--------|-------------|
| `Prepare` | State preparation |
| `Measure` | Quantum measurement |
| `Send` | Transmit to target |
| `Receive` | Receive from target |
| `Compute` | Classical computation |
| `Announce` | Public announcement |

## Security Goal Types

### Key Agreement

```go
type KeyAgreement struct {
    KeyLength    int       // Desired key length
    ErrorRate    *Rat      // Maximum tolerable QBER
    SecrecyBound *Rat      // Information leakage bound
}
```

### State Transfer

```go
type StateTransfer struct {
    InputDim  int   // Input Hilbert space dimension
    OutputDim int   // Output Hilbert space dimension
    Fidelity  *Rat  // Required fidelity
}
```

### Secret Sharing

```go
type SecretSharing struct {
    Threshold int  // Minimum parties to reconstruct
    Total     int  // Total number of parties
}
```

### Bit Commitment

```go
type BitCommitment struct {
    Binding *Rat  // Binding parameter
    Hiding  *Rat  // Hiding parameter
}
```

### Coin Flip

```go
type CoinFlip struct {
    Bias *Rat  // Cheating bias (Kitaev bound: >= 1/sqrt(2) - 1/2)
}
```

### Oblivious Transfer

```go
type ObliviousTransfer struct {
    SenderPrivacy   *Rat  // Sender's privacy parameter
    ReceiverPrivacy *Rat  // Receiver's privacy parameter
}
```

## Security Assumptions

| Assumption | Description |
|------------|-------------|
| `NoCloning` | Quantum no-cloning theorem |
| `AuthenticatedClassical` | Authenticated classical channel |
| `NoSideChannel` | No side-channel information leakage |
| `PerfectDevices` | Ideal quantum devices |
| `IIDAttacks` | Attacks are i.i.d. across signals |

## Witness and Certificate Structure

### Witness Types

| Type | Content |
|------|---------|
| `ChoiMatrix` | Channel representation as Choi-Jamiolkowski matrix |
| `SecurityBound` | Key rate and epsilon parameters |
| `KeyRate` | Achievable key rate with attack model |
| `NoiseTolerance` | Noise threshold for security |
| `CompositionProof` | Protocol composition certificate |
| `EntropyBound` | Entropy bounds (symbolic + numeric) |
| `AttackAnalysis` | Attack resistance analysis |
| `ChoiEquality` | Equality proof for two channels |
| `InformationBound` | Mutual information I(X:E) bound |

### Witness Structure

```go
type Witness struct {
    Type        WitnessType     // Kind of witness
    Description string          // Human-readable description
    Data        runtime.Value   // Witness data
    Assumptions []string        // Required assumptions
}
```

### Evidence

```go
type Evidence struct {
    Claim      Claim      // The assertion being proved
    Witness    *Witness   // Supporting witness
    Status     Status     // verified, pending, failed
    Derivation string     // Proof derivation
}
```

### Certificate Bundle

```go
type Bundle struct {
    Protocol string
    Evidence []*Evidence
    Metadata map[string]string
}
```

## Command Dispatch

### Commands

| Command | Function |
|---------|----------|
| `CmdSynth` | Synthesize protocol circuit |
| `CmdVerify` | Verify correctness |
| `CmdSecurity` | Compute security bounds |
| `CmdAttack` | Attack analysis |
| `CmdNoise` | Noise tolerance |
| `CmdCompose` | Protocol composition |
| `CmdFullAnalysis` | Complete certification |
| `CmdList` | List protocols |
| `CmdInfo` | Protocol information |

### Dispatch Options

```go
type DispatchOptions struct {
    ErrorRate      *big.Rat  // QBER for analysis
    AdversaryModel string    // "individual", "collective", "coherent"
    NoiseModel     string    // "depolarizing", "amplitude_damping", etc.
    Verbose        bool      // Detailed output
    OutputFormat   string    // "text", "json", "qmb"
}
```

## .qmb Binary Format

The `.qmb` format is an embedded binary containing:

1. **Header**: Magic bytes `QMB1`
2. **Metadata**: Model name, version
3. **Store**: Content-addressed value store (QGID-indexed)
4. **Entrypoint**: QGID of the main model value

### Encoding

Values are encoded using a tagged format:

| Tag | Type |
|-----|------|
| `0x00` | Nil |
| `0x01` | Bool |
| `0x02` | Int (big integer) |
| `0x03` | Rat (rational) |
| `0x04` | Text (UTF-8 string) |
| `0x05` | Bytes |
| `0x06` | Seq (sequence/list) |
| `0x07` | Tag (labeled value) |
| `0x08` | Matrix |

### QGID

Every value has a QGID (Quantum Global Identifier) computed as:

```
QGID = SHA-256(encoded_value)
```

This provides content-addressed storage and integrity verification.

## Choi Matrix Representation

Channels are represented via the Choi-Jamiolkowski isomorphism.

For a channel `Phi: B(H_A) -> B(H_B)`:

```
J(Phi) = (id_A tensor Phi)(|Omega><Omega|)
```

Where `|Omega> = (1/sqrt(d)) * sum_i |i>|i>` is the maximally entangled state.

### Correctness Verification

Two channels are identical if and only if their Choi matrices are equal:

```
Phi_1 = Phi_2  <=>  J(Phi_1) = J(Phi_2)
```

This is verified by exact rational matrix comparison.

## Kraus Representation

Channels can also be represented by Kraus operators `{K_i}`:

```
Phi(rho) = sum_i K_i * rho * K_i^dagger
```

The completeness condition ensures trace preservation:

```
sum_i K_i^dagger * K_i = I
```

## Attack Categories

| Category | Description | Memory |
|----------|-------------|--------|
| Individual | i.i.d. operations per signal | None |
| Collective | Collective measurement post-processing | Classical |
| Coherent | Full quantum processing | Quantum |
| Implementation | Device imperfections | N/A |

## Security Bounds

### Key Rate Formulas

| Protocol | Key Rate | Threshold |
|----------|----------|-----------|
| BB84 | `r = 1 - 2h(e)` | e < 11% |
| E91 | `r = 1 - h((1+sqrt((S/2)^2-1))/2)` | S > 2 |
| Six-State | `r = 1 - (5/3)h(3e/2)` | e < 16.67% |
| B92 | `r = (1/2)(1 - h(2e))` | e < 25% |
| SARG04 | `r = 1 - 2h(e) - f(mu)` | e < 10% |

Where `h(x)` is binary entropy: `h(x) = -x*log2(x) - (1-x)*log2(1-x)`

### Devetak-Winter Bound

For coherent attacks:

```
r >= H(X|E) - H(X|Y)
```

Using smooth min-entropy for finite-key analysis.

## Noise Models

| Model | Kraus Operators | QBER |
|-------|-----------------|------|
| Depolarizing | `K_0=sqrt(1-p)I`, `K_i=sqrt(p/3)sigma_i` | `2p/3` |
| Amplitude Damping | `K_0=[[1,0],[0,sqrt(1-gamma)]]`, `K_1=[[0,sqrt(gamma)],[0,0]]` | `gamma/2` |
| Phase Damping | `K_0=sqrt(1-lambda)I`, `K_1=sqrt(lambda)Z` | `lambda/2` |
| Bit Flip | `K_0=sqrt(1-p)I`, `K_1=sqrt(p)X` | `p` |
| Phase Flip | `K_0=sqrt(1-p)I`, `K_1=sqrt(p)Z` | `0` (no bit error) |
