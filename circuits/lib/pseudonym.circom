pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

// A per-verifier pseudonym: Poseidon(holderSecret, domainHash).
//   - Same holder, same verifier  -> same value every time (a returning user).
//   - Same holder, other verifier -> an unrelated value (no cross-site linking).
// It is revealed only when `enabled` is 1; otherwise the output is 0.
template ScopedPseudonym() {
    signal input holderSecret;
    signal input domainHash;
    signal input enabled;
    signal output out;

    // RULE: enabled is 0 or 1
    enabled * (enabled - 1) === 0;

    component hash = Poseidon(2);
    hash.inputs[0] <== holderSecret;
    hash.inputs[1] <== domainHash;

    out <== enabled * hash.out;
}
