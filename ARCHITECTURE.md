# QBTM Architecture (v2.0.0)

Technical documentation for the Quantum Block Type Morphisms runtime and protocol certifier.

## Design Principles

1. **Zero Dependencies**: Only Go standard library
2. **Exact Arithmetic**: No floating-point approximations (Q(i) = Gaussian rationals)
3. **Content Addressing**: Values identified by cryptographic hashes (QGID)
4. **Self-Containment**: .qmb files include all required data with complete round-trip
5. **Self-Verification**: Bootstrap fixpoint proves implementation correctness
6. **Security as Artifacts**: Proofs are executable, not paper claims

## System Components

| Component | Purpose | Location |
|-----------|---------|----------|
| **Runtime** | Circuit execution | `runtime/` |
| **Certify** | Protocol analysis | `certify/` |
| **CLI** | User interface | `cmd/qbtm/`, `cmd/certify/` |
| **Models** | Generated artifacts | `models/`, `examples/` |

## Module Structure

### `runtime/value.go`

Core value types for the quantum model representation. All 8 types fully round-trip through binary encoding and decoding.

```go
type Value interface {
    valueTag()
    Encode() []byte
}
```

**Value Types (all with complete Encode/Decode round-trip):**
| Type | Description | Encoding Prefix |
|------|-------------|-----------------|
| `Int` | Arbitrary-precision integer | 0x00-0x3F (small), 0x40 (positive), 0x80 (negative) |
| `Rat` | Arbitrary-precision rational | 0x90 (sign + num/denom bytes) |
| `Bytes` | Raw byte sequence | 0xA0 (varint length + data) |
| `Text` | UTF-8 string | 0xB0 (varint length + data) |
| `Seq` | Ordered sequence of values | 0xC0 (varint count + items) |
| `Tag` | Labeled value (discriminated union) | 0xD0 (label + payload) |
| `Bool` | Boolean | 0xE0 (false) / 0xE1 (true) |
| `Nil` | Unit value | 0xF0 |

**QGID Computation:**
```go
func QGID(v Value) [32]byte {
    return sha256.Sum256(v.Encode())
}
```

### `runtime/arithmetic.go`

Exact arithmetic over Gaussian rationals Q(i) = {a + bi : a,b in Q}:

```go
type QI struct {
    Re *big.Rat  // Real part
    Im *big.Rat  // Imaginary part
}
```

**Matrix Type:**
```go
type Matrix struct {
    Rows, Cols int
    Data       []QI  // Row-major order
}
```

**Operations:**
- `MatMul(A, B)` - Matrix multiplication
- `Kronecker(A, B)` - Kronecker (tensor) product
- `Dagger(M)` - Conjugate transpose (M†)
- `Trace(M)` - Matrix trace
- `MatAdd(A, B)` - Matrix addition
- `MatScale(M, r)` - Scalar multiplication
- `Identity(n)` - n x n identity matrix
- `MatrixFromValue(v)` / `MatrixToValue(m)` - Value conversion

### `runtime/exec.go`

Circuit interpreter that executes all 23 quantum morphism primitives:

```go
type Executor struct {
    store *Store
}

func (e *Executor) Execute(c Circuit, input *Matrix) (*Matrix, error)
```

**Complete Dispatch (all 23 primitives):**
```go
switch c.Prim {
case PrimId:        // Identity
case PrimCompose:   // Sequential composition
case PrimTensor:    // Parallel (Kronecker product)
case PrimSwap:      // Permutation matrix
case PrimBisum:     // Block-diagonal
case PrimInject:    // Embed in larger matrix
case PrimProject:   // Extract block
case PrimCopy:      // Classical duplication
case PrimDelete:    // Classical deletion (trace)
case PrimEncode:    // Classical-to-quantum
case PrimDecode:    // Quantum-to-classical (diagonal extraction)
case PrimUnitary:   // U ρ U†
case PrimChoi:      // Choi-Jamiolkowski isomorphism
case PrimKraus:     // Σ_k K_k ρ K_k†
case PrimPrepare:   // State preparation
case PrimDiscard:   // Complete trace
case PrimTrace:     // Quantum trace
case PrimAdd:       // Matrix addition of sub-results
case PrimScale:     // Scalar multiplication
case PrimZero:      // Zero matrix
case PrimAssert:    // Type assertion
case PrimWitness:   // Proof artifact
}
```

**Supporting Types:**
```go
type Circuit struct {
    Domain   Object      // Input C*-algebra type
    Codomain Object      // Output C*-algebra type
    Prim     Prim        // Primitive operation (0-22)
    Data     Value       // Auxiliary data (matrices, scalars, etc.)
    Children [][32]byte  // Child circuit QGIDs
}

type Object struct {
    Blocks []uint32      // Block sizes: [2] = Q(2), [1,1] = C(2), [] = I
}
```

### `runtime/embed.go`

Binary format handling with complete round-trip serialization:

```go
type EmbeddedBinary struct {
    Magic      [4]byte   // "QMB\x01"
    Entrypoint [32]byte  // QGID of entrypoint circuit
    Name       string    // Binary name
    Version    string    // Version string
    StoreData  []byte    // Serialized value store
}
```

**Binary Layout:**
1. Magic bytes: `QMB\x01` (4 bytes)
2. Entrypoint QGID (32 bytes)
3. Name (4-byte big-endian length + UTF-8 data)
4. Version (4-byte big-endian length + UTF-8 data)
5. Store data (remaining bytes)

**Store Serialization Format:**

The store is serialized as a `Seq` of `Tag("entry", Seq(Bytes(qgid), value))` pairs:
```
Seq(
  Tag("entry", Seq(Bytes(qgid_1), circuit_value_1)),
  Tag("entry", Seq(Bytes(qgid_2), circuit_value_2)),
  ...
)
```

**Complete Value Decoder:**

The `decodeValue` function in embed.go is the complete inverse of the `Encode()` methods. It handles all 8 value types, including nested structures (Seq of Seq, Tag of Tag, etc.), enabling full round-trip of arbitrary .qmb files.

**Import Process:**

When loading a .qmb file, each entry's value is tested as a circuit via `CircuitFromValue`. If it parses, it is stored as both a circuit and a value; otherwise as a plain value.

### `runtime/synth.go`

Synthesis engine providing 12 synthesis rules, 4 rewrite rules, and the bootstrap mechanism:

```go
type SynthesisSpec struct {
    Name     string
    Domain   Object
    Codomain Object
}

type SynthesisRule struct {
    Name    string
    Match   func(spec SynthesisSpec) bool
    Produce func(store *Store, spec SynthesisSpec) (Circuit, [][32]byte)
}

type RewriteRule struct {
    Name  string
    Apply func(c Circuit, store *Store) (Circuit, bool)
}
```

**Key Functions:**
- `Synthesize(store, spec)` - Synthesize a circuit from a specification
- `AllSynthesisRules()` - Returns all 12 synthesis rules
- `AllRewriteRules()` - Returns all 4 rewrite rules
- `NormalizeCircuit(c, store)` - Apply all rewrite rules to fixpoint
- `Bootstrap()` - Run the self-reproducing fixpoint demonstration

## Execution Model

### Type Objects

Block types represent C*-algebras:

```
Object{Blocks: []uint32}
```

- `Q(n)` = `Object{Blocks: []uint32{n}}` - n-dimensional quantum (M_n(C))
- `C(k)` = `Object{Blocks: []uint32{1,1,...,1}}` - k classical levels
- `I` = `Object{Blocks: []uint32{}}` - unit (monoidal identity)

Two dimension functions:
- `objectDim(obj)` - Density matrix dimension: sum of n^2 for each block n
- `BlockDim(obj)` - Hilbert space dimension: sum of block sizes

### Circuit Execution

1. **Load**: Parse .qmb, decode all values, populate store
2. **Resolve**: Lookup entrypoint QGID in store
3. **Execute**: Recursively evaluate circuit by dispatching on `Prim`
4. **Output**: Final density matrix representing the morphism applied to input

The `run` command auto-detects input dimension from the entrypoint circuit's domain.

### Matrix Semantics

- **State**: Density matrix rho (positive, trace 1)
- **Channel**: CPTP map (completely positive, trace-preserving)
- **Effect**: POVM element (positive, bounded by I)

Composition: `(g . f)(rho) = g(f(rho))`
Tensor: `(f x g)(rho x sigma) = f(rho) x g(sigma)`

## Self-Bootstrap Property

The QBTM system is self-reproducing. The `Bootstrap()` function demonstrates this:

```
Step 1: Build toolchain v1 with intentional redundancy: Compose(toolchain, Id)
Step 2: NormalizeCircuit applies LeftIdentity → removes redundant Id → v2
Step 3: Rebuild from v2's normalized form → v3
Step 4: SHA-256(v2) == SHA-256(v3) → FIXPOINT PROVEN
```

This proves self-consistency: the normalized synthesis toolchain reproduces itself exactly through the full Embed/Decode/Normalize cycle.

### Why This Works

The fixpoint depends on three properties working together:
1. **Complete value encoding**: All 8 value types encode deterministically
2. **Complete value decoding**: `decodeValue` is the exact inverse of `Encode()`
3. **Normalization convergence**: Rewrite rules reach a fixpoint (canonical form)

## Memory Model

All values are immutable. The store is a pure function from QGID to Value:

```
store : [32]byte -> Value
```

Content addressing provides:
- Automatic deduplication
- Referential transparency
- Cryptographic verification

## Performance Characteristics

| Operation | Complexity |
|-----------|-----------|
| QGID lookup | O(1) hash table |
| Matrix multiply (n x n) | O(n^3) |
| Kronecker product (m x n) | O(mn) space |
| Rational arithmetic | Depends on bit-length |

Note: Exact arithmetic can lead to exponential growth in numerator/denominator sizes for deep circuits. The runtime makes no attempt to limit this.

## Error Handling

The runtime returns errors for:
- Invalid magic bytes in .qmb
- Missing QGID references
- Type mismatches (dimension errors)
- Malformed value encodings

All errors are wrapped with context for debugging.

## Security Considerations

- .qmb files are not sandboxed (execute arbitrary circuit logic)
- Large circuits can exhaust memory (no resource limits)
- Untrusted .qmb files should be inspected before execution

---

## Protocol Certifier (`certify/`)

The certify package provides formal security analysis for quantum protocols.

### Package Structure

```
certify/
├── protocol/              # Protocol Specifications
│   ├── spec.go            # Core types (Protocol, Party, Resource, Goal)
│   ├── qkd/               # QKD: BB84, E91, B92, Six-State, SARG04
│   ├── communication/     # Teleportation, Superdense, Swapping
│   ├── multiparty/        # GHZ, W-State, Secret Sharing
│   └── cryptographic/     # Coin Flip, Bit Commitment, OT
├── attack/                # Attack Library (21 attacks)
│   ├── individual.go      # Intercept-resend, cloning, USD
│   ├── collective.go      # Collective measurement, Devetak-Winter
│   ├── coherent.go        # General coherent, composable
│   └── implementation.go  # PNS, detector blinding, etc.
├── analysis/              # Analysis Engine
│   ├── correctness.go     # Choi matrix verification
│   ├── security.go        # Key rate computation
│   ├── entropy.go         # Symbolic entropy h(e)
│   ├── noise.go           # Noise tolerance
│   └── composition.go     # Protocol composition
├── certificate/           # Certificate Generation
│   ├── evidence.go        # Evidence bundles
│   ├── witness.go         # Proof witnesses
│   ├── claim.go           # Security claims
│   └── bundle.go          # Full analysis bundles
├── model.go               # Model construction
├── dispatch.go            # Command dispatch
└── emit.go                # .qmb emission
```

### Security Analysis Pipeline

```
Protocol Spec → Synthesize → Verify Correctness → Compute Security → Generate Certificate
     │              │               │                    │                    │
     ▼              ▼               ▼                    ▼                    ▼
  spec.go       circuit QGID   Choi matrix          Key rate            Evidence bundle
                               comparison            bounds
```

### Symbolic Entropy

Security bounds use symbolic entropy with rational bounds:

```go
type Entropy struct {
    Symbolic string      // "1 - 2h(e)"
    Lower    *big.Rat    // Computable lower bound
    Upper    *big.Rat    // Computable upper bound
}

// Key rate for BB84: r = 1 - 2h(e)
// Threshold: e < 11/100 (exactly)
```

### Attack Interface

All attacks implement:

```go
type Attack interface {
    Name() string
    ChoiMatrix() *runtime.Matrix      // CP map representation
    InformationGained() *big.Rat      // Exact rational
    DisturbanceInduced() *big.Rat     // Exact rational
    ApplicableProtocols() []string
}
```

### Certificate Structure

```go
type Evidence struct {
    Status    Status    // Verified, Failed, Conditional
    Claim     *Claim    // What is being claimed
    Witness   *Witness  // Proof artifact
}

type Bundle struct {
    Protocol  string
    Evidence  []*Evidence   // Multiple claims proven
}
```

### Key Formulas (Exact Rationals)

| Protocol | Key Rate | Threshold |
|----------|----------|-----------|
| BB84 | r = 1 - 2h(e) | e < 11/100 |
| Six-State | r = 1 - (5/3)h(3e/2) | e < 1/6 |
| E91 | Based on CHSH | S > 2 |
| Coin Flip | Bias ≥ (√2-1)/2 | Kitaev bound |
