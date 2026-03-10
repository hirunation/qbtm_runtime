# QBTM Protocol Certifier

Self-contained model for synthesizing, verifying, and certifying quantum communication protocols with exact security bounds over Q(i).

## Quick Start

### Build the CLI

```bash
go build -o certify ./cmd/certify
```

### Analyze a Protocol

```bash
# Full analysis of BB84
./certify full-analysis BB84

# Verify correctness of teleportation
./certify verify Teleportation

# Check security bounds
./certify security E91 --error-rate 0.05

# List available protocols
./certify list
```

### Generate the Model

```bash
go run ./cmd/certify-gen
# Creates models/certify/qbtm_certify.qmb
```

## Features

- **14 Quantum Protocols**: QKD (BB84, E91, B92, Six-State, SARG04), Communication (Teleportation, SuperdenseCoding, EntanglementSwapping), Multi-party (GHZ, W-State, SecretSharing), Cryptographic (CoinFlip, BitCommitment, ObliviousTransfer)
- **21 Attack Models**: Individual, collective, coherent, and implementation attacks
- **Exact Arithmetic**: All security bounds use Q(i) (Gaussian rationals), no floating-point
- **Formal Verification**: Correctness via Choi matrix comparison
- **Security Analysis**: Key rates, thresholds, noise tolerance

## CLI Commands

| Command | Description |
|---------|-------------|
| `synth` | Synthesize protocol model from specification |
| `verify` | Verify protocol correctness via Choi matrix |
| `security` | Compute security bounds (key rate, epsilon) |
| `attack` | Analyze resistance to specified attack model |
| `noise` | Analyze noise tolerance thresholds |
| `compose` | Compose multiple protocols |
| `full-analysis` | Run complete certification pipeline |
| `list` | List all available protocols |
| `info` | Show detailed protocol information |

## CLI Options

| Option | Description |
|--------|-------------|
| `--attack` | Attack model: `individual`, `collective`, `coherent` (default: coherent) |
| `--noise` | Noise model: `depolarizing`, `amplitude_damping`, `phase_damping` |
| `--error-rate` | QBER for analysis (e.g., `1/100` for 1%) |
| `--format` | Output format: `text`, `json`, `qmb` (default: text) |
| `--output`, `-o` | Output file path (default: stdout) |
| `--self-verify` | Verify correctness before emitting (default: true) |
| `--verbose` | Include detailed derivations |

## Examples

```bash
# Synthesize BB84 circuit
./certify synth BB84

# Security analysis with specific adversary model
./certify security --attack=coherent BB84

# Noise tolerance analysis
./certify noise --noise=depolarizing BB84

# Compose protocols
./certify compose BB84 Teleportation

# Full analysis with JSON output
./certify full-analysis --format=json --output=bb84_analysis.json BB84

# Generate certified .qmb file
./certify full-analysis --format=qmb --output=bb84_cert.qmb BB84

# Get protocol information
./certify info Six-State
```

## Model Format

The `.qmb` format is a binary embedding of the certified model with:

- Protocol specification
- Synthesized circuit
- Correctness certificate (Choi matrix witness)
- Security bounds
- Attack analysis results

## Architecture

```
certify/
  protocol/           # Protocol definitions
    qkd/              # QKD protocols (BB84, E91, B92, Six-State, SARG04)
    communication/    # Communication protocols (Teleportation, Superdense, Swapping)
    multiparty/       # Multi-party protocols (GHZ, W-State, SecretSharing)
    cryptographic/    # Cryptographic primitives (CoinFlip, BitCommitment, OT)
  attack/             # Attack library (individual, collective, coherent)
  analysis/           # Analysis engine (correctness, security, noise, composition)
  certificate/        # Certificate generation (evidence, witnesses, bundles)
```

## Model QGID

```
QMB1 (embedded binary format)
Name: qbtm_certify
Version: 1.0.0
```

## Documentation

- [SPECIFICATION.md](SPECIFICATION.md) - Technical specification
- [PROTOCOLS.md](PROTOCOLS.md) - Protocol catalog
- [CAPABILITIES.md](CAPABILITIES.md) - Capabilities and limitations
