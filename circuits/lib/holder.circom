pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

// RULE: the prover knows the secret behind the credential's holder commitment,
//   Poseidon(holderSecret) == commitment.
// A copied credential is useless without the secret.
template HolderBinding() {
    signal input holderSecret;
    signal input commitment;

    component hash = Poseidon(1);
    hash.inputs[0] <== holderSecret;
    hash.out === commitment;
}
