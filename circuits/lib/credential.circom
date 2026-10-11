pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";

// Checks that `attrs` is a credential signed by the issuer key (Ax, Ay):
//   M = Poseidon(attrs), and (R8x, R8y, S) is a valid EdDSA signature on M.
template VerifyCredential(nAttrs) {
    signal input attrs[nAttrs];
    signal input R8x;
    signal input R8y;
    signal input S;
    signal input Ax;
    signal input Ay;

    // M = Poseidon(attr[0], ..., attr[nAttrs-1])
    component hash = Poseidon(nAttrs);
    for (var i = 0; i < nAttrs; i++) {
        hash.inputs[i] <== attrs[i];
    }

    // RULE: the issuer really signed M
    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax  <== Ax;
    sig.Ay  <== Ay;
    sig.R8x <== R8x;
    sig.R8y <== R8y;
    sig.S   <== S;
    sig.M   <== hash.out;
}
