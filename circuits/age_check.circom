pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";

template AgeCheck() {
    // ---- Private inputs (only the holder knows) ----
    signal input dob;
    signal input R8x;     // issuer signature, part 1
    signal input R8y;     // issuer signature, part 2
    signal input S;       // issuer signature, part 3

    // ---- Public inputs (the verifier sees these) ----
    signal input today;
    signal input Ax;      // issuer public key, x
    signal input Ay;      // issuer public key, y

    // 1. Hash the credential: M = Poseidon(dob)
    component hash = Poseidon(1);
    hash.inputs[0] <== dob;

    // 2. RULE: the issuer really signed M
    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax  <== Ax;
    sig.Ay  <== Ay;
    sig.R8x <== R8x;
    sig.R8y <== R8y;
    sig.S   <== S;
    sig.M   <== hash.out;

    // 3. Range checks (same as before)
    component dobBits = Num2Bits(32);
    dobBits.in <== dob;

    component todayBits = Num2Bits(32);
    todayBits.in <== today;

    signal threshold;
    threshold <== today - 180000;

    component thresholdBits = Num2Bits(32);
    thresholdBits.in <== threshold;

    // 4. RULE: dob <= today - 18 years
    component le = LessEqThan(32);
    le.in[0] <== dob;
    le.in[1] <== threshold;
    le.out === 1;
}

component main {public [today, Ax, Ay]} = AgeCheck();