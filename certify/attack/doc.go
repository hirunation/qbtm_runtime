// Package attack provides quantum attack models as CP maps.
//
// Attacks are modeled as completely positive maps that an adversary
// can apply to intercepted quantum states. Each attack specifies:
//
//   - Information gained by the adversary (exact rational)
//   - Disturbance induced on the legitimate channel (exact rational)
//   - Applicable protocols
//
// # Attack Categories
//
//   - Individual attacks: Applied independently to each signal (intercept-resend, cloning, USD)
//   - Collective attacks: Collective measurement on all intercepted signals
//   - Coherent attacks: Most general attack with quantum memory
//   - Implementation attacks: Exploit device imperfections (PNS, detector blinding)
package attack
