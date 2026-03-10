# QBTM Protocol Catalog

This document catalogs all 14 quantum protocols implemented in the certifier.

---

## QKD Protocols

### BB84

**Type**: `(C(2) x C(2))^n -> C(2)^m`

**Description**: Bennett-Brassard 1984 quantum key distribution protocol using four states in two conjugate bases. The first and most widely used QKD protocol.

**States**:
- Z-basis: |0>, |1>
- X-basis: |+>, |->

**Key Rate**: `r = 1 - 2h(e)` where `h` is binary entropy

**Threshold**: `e < 11/100` (11%)

**Security**: Unconditionally secure against coherent attacks under authenticated classical channel assumption.

**Assumptions**:
- No-Cloning
- Authenticated Classical Channel

**Reference**: Bennett & Brassard, 1984

---

### E91

**Type**: `(C(4))^n -> C(2)^m`

**Description**: Ekert 1991 entanglement-based QKD protocol using CHSH inequality violation for security verification. Uses maximally entangled Bell pairs.

**States**: Bell pair |Phi+> = (|00> + |11>)/sqrt(2)

**Measurement Angles**:
- Alice: {0, pi/4, pi/2}
- Bob: {pi/4, pi/2, 3*pi/4}

**Key Rate**: `r = 1 - h((1 + sqrt((S/2)^2 - 1))/2)` where S is CHSH value

**CHSH Bounds**:
- Classical: S <= 2
- Quantum Maximum: S = 2*sqrt(2) ~ 2.828

**Threshold**: S > 2 (CHSH violation)

**Security**: Device-independent security possible via Bell inequality violation.

**Assumptions**:
- No-Signaling (space-like separated measurements)
- Authenticated Classical Channel
- Entanglement Source

**Reference**: Ekert, 1991

---

### B92

**Type**: `C(2)^n -> C(2)^m`

**Description**: Bennett 1992 two-state QKD protocol using only two non-orthogonal states. Simpler than BB84 but requires single-photon source.

**States**:
- |0> (bit 0)
- |+> (bit 1)

State overlap: `|<0|+>|^2 = 1/2`

**Key Rate**: `r = (1/2) * (1 - h(2e))`

**Threshold**: `e < 1/4` (25%)

**Conclusive Rate**: 50% (inconclusive measurements discarded)

**Vulnerability**: Susceptible to Unambiguous State Discrimination (USD) attacks.

**Assumptions**:
- No-Cloning
- Authenticated Classical Channel
- Single-Photon Source (vulnerable to USD otherwise)

**Reference**: Bennett, 1992

---

### Six-State

**Type**: `(C(2) x C(3))^n -> C(2)^m`

**Description**: Six-state QKD protocol using three mutually unbiased bases (X, Y, Z) for improved noise tolerance over BB84.

**States**:
- Z-basis: |0>, |1>
- X-basis: |+>, |->
- Y-basis: |+i>, |-i>

**Key Rate**: `r = 1 - (5/3)h(3e/2)`

**Threshold**: `e < 1/6` (16.67%)

**Sifting Rate**: 1/3 (matching bases)

**Noise Advantage**: Tolerates ~1.5x more noise than BB84

**Assumptions**:
- No-Cloning
- Authenticated Classical Channel

**Reference**: Bruss, 1998; Lo, 2001

---

### SARG04

**Type**: `(C(2) x C(2))^n -> C(2)^m`

**Description**: Scarani-Acin-Ribordy-Gisin 2004 protocol. PNS-resistant variant of BB84 that announces non-orthogonal state pairs instead of bases.

**States**: Same as BB84 (|0>, |1>, |+>, |->)

**Announcement**: Non-orthogonal state pairs:
- Pair 0: {|0>, |+>}
- Pair 1: {|1>, |->}
- Pair 2: {|+>, |1>}
- Pair 3: {|->, |0>}

**Key Rate**: `r = 1 - 2h(e) - f(mu)` where mu is mean photon number

**Threshold**: `e < 10/100` (10%)

**Conclusive Rate**: 25% (vs BB84's 50%)

**PNS Resistance**: ~2x improvement over BB84 for weak coherent sources

**Assumptions**:
- No-Cloning
- Authenticated Classical Channel
- Weak Coherent Source (typical implementation)

**Reference**: Scarani, Acin, Ribordy & Gisin, 2004

---

## Communication Protocols

### Teleportation

**Type**: `Q(2) x Bell -> Q(2)`

**Description**: Bennett et al. 1993 quantum teleportation. Transfers an unknown quantum state using pre-shared entanglement and classical communication.

**Protocol Steps**:
1. Alice has unknown qubit |psi> and half of Bell pair
2. Alice performs Bell measurement
3. Alice sends 2 classical bits to Bob
4. Bob applies correction (I, X, Z, or XZ)
5. Bob's qubit is now |psi>

**Fidelity**: 1 (exact, perfect transfer)

**Resources**: 1 Bell pair + 2 classical bits

**Assumptions**:
- Pre-shared Entanglement
- Classical Communication

**Reference**: Bennett et al., 1993

---

### SuperdenseCoding

**Type**: `C(2) x C(2) x Bell -> Q(2)`

**Description**: Transmit 2 classical bits using 1 qubit and pre-shared entanglement. The dual of teleportation.

**Protocol Steps**:
1. Alice shares Bell pair with Bob
2. Alice applies one of {I, X, Z, XZ} to her qubit based on 2-bit message
3. Alice sends her qubit to Bob
4. Bob performs Bell measurement to recover 2 bits

**Capacity**: 2 classical bits per qubit

**Resources**: 1 Bell pair + 1 qubit channel

**Assumptions**:
- Pre-shared Entanglement

**Reference**: Bennett & Wiesner, 1992

---

### EntanglementSwapping

**Type**: `Bell x Bell -> Bell`

**Description**: Entanglement swapping for quantum repeaters. Creates entanglement between parties that never interacted.

**Protocol Steps**:
1. Alice shares Bell pair with Charlie
2. Bob shares Bell pair with Charlie
3. Charlie performs Bell measurement on his two qubits
4. Alice and Bob now share entanglement

**Application**: Quantum repeaters for long-distance QKD

**Assumptions**:
- Two Entangled Pairs
- Bell Measurement capability

**Reference**: Zukowski et al., 1993

---

## Multi-party Protocols

### GHZ

**Type**: `Q(1) -> Q(2)^n`

**Description**: GHZ (Greenberger-Horne-Zeilinger) state distribution for n parties.

**State**: `|GHZ_n> = (|0...0> + |1...1>) / sqrt(2)`

**Properties**:
- Maximally entangled n-party state
- Single qubit loss destroys all entanglement
- All parties measuring in same basis get same outcome

**Preparation Circuit**:
```
q0: -[H]-*---*---*--- ...
         |   |   |
q1: -----X---+---+--- ...
             |   |
q2: ---------X---+--- ...
                 |
q3: -------------X--- ...
```

**Applications**: Multi-party secret sharing, anonymous broadcasting

**Assumptions**:
- Multiparty Quantum Channels

**Reference**: Greenberger, Horne & Zeilinger, 1989

---

### W-State

**Type**: `Q(1) -> Q(2)^n`

**Description**: W state distribution for n parties. More robust to particle loss than GHZ.

**State**: `|W_n> = (|100...0> + |010...0> + ... + |000...1>) / sqrt(n)`

**Properties**:
- Entanglement survives single particle loss
- Less entanglement than GHZ but more robust
- Useful for quantum networks

**Robustness**: Tracing out one qubit leaves (n-1)-party entanglement

**Assumptions**:
- Multiparty Quantum Channels

**Reference**: Dur, Vidal & Cirac, 2000

---

### SecretSharing

**Type**: `C(2) x GHZ_n -> C(2)^n`

**Description**: Quantum secret sharing using GHZ states. (k,n) threshold scheme where k parties must cooperate to reconstruct secret.

**Protocol**:
1. Dealer encodes secret into GHZ state
2. Distributes qubits to n parties
3. Any k parties can reconstruct, fewer learn nothing

**Security**: Information-theoretic security against k-1 colluding parties

**Assumptions**:
- Multiparty Quantum Channels
- Threshold Access Structure

**Reference**: Hillery, Buzek & Berthiaume, 1999

---

## Cryptographic Primitives

### CoinFlip

**Type**: `Q(2) -> C(2)`

**Description**: Quantum coin flipping protocol for fair random bit generation between distrustful parties.

**Kitaev Bound**: No quantum protocol can have cheating bias less than `1/sqrt(2) - 1/2 ~ 0.207`

**Achievable Bias**: Approximately 0.21 with optimal protocols

**Security Goal**: Both parties should have equal influence on outcome

**Assumptions**:
- Quantum Communication

**Reference**: Kitaev, 2003 (impossibility bound); Chailloux & Kerenidis, 2009

---

### BitCommitment

**Type**: `C(2) -> Commit x Reveal`

**Description**: Quantum bit commitment protocol. Allows committing to a bit while keeping it hidden, then revealing later.

**Impossibility**: Perfect quantum bit commitment is impossible (Mayers-Lo-Chau theorem)

**Trade-off**: `binding + hiding >= 1` (cannot have both perfectly)

**Achievable**: Protocols with bounded cheating probabilities

**Assumptions**:
- Quantum Communication

**Reference**: Mayers, 1997; Lo & Chau, 1997

---

### ObliviousTransfer

**Type**: `(C(2) x C(2)) x C(2) -> C(2)`

**Description**: Quantum 1-2 oblivious transfer. Alice has two bits, Bob chooses one without Alice learning which.

**Security Goals**:
- Sender Privacy: Bob learns only one bit
- Receiver Privacy: Alice doesn't learn Bob's choice

**Impossibility**: Perfect quantum OT is impossible (follows from bit commitment impossibility)

**Applications**: Basis for secure multi-party computation

**Assumptions**:
- Quantum Communication
- Bit Commitment (as subroutine)

**Reference**: Crepeau, 1994

---

## Protocol Summary Table

| Protocol | Type | Threshold | Key Feature |
|----------|------|-----------|-------------|
| BB84 | QKD | 11% | First QKD protocol |
| E91 | QKD | S > 2 | Entanglement-based, device-independent |
| B92 | QKD | 25% | Two-state, minimal |
| Six-State | QKD | 16.67% | Higher noise tolerance |
| SARG04 | QKD | 10% | PNS-resistant |
| Teleportation | Comm | N/A | State transfer |
| SuperdenseCoding | Comm | N/A | 2 bits per qubit |
| EntanglementSwapping | Comm | N/A | Quantum repeater |
| GHZ | Multi | N/A | n-party entanglement |
| W-State | Multi | N/A | Robust entanglement |
| SecretSharing | Multi | N/A | Threshold scheme |
| CoinFlip | Crypto | N/A | Fair randomness |
| BitCommitment | Crypto | N/A | Commit-reveal |
| ObliviousTransfer | Crypto | N/A | 1-2 OT |
