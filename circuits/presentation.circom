pragma circom 2.1.6;

include "lib/credential.circom";
include "lib/predicate.circom";

// A presentation: "I hold a credential signed by this issuer,
// and its attributes satisfy these predicates".
template Presentation(nAttrs, nPreds) {
    // ---- Private inputs (only the holder knows) ----
    signal input attrs[nAttrs];   // the 10-slot attribute vector, see docs/encoding.md
    signal input R8x;             // issuer signature
    signal input R8y;
    signal input S;

    // ---- Public inputs (the verifier supplies these) ----
    signal input Ax;              // issuer public key
    signal input Ay;
    signal input predAttr[nPreds];    // which slot each predicate is about
    signal input predOp[nPreds];      // 0 none, 1 ==, 2 >=, 3 <=
    signal input predValue[nPreds];   // the value to compare against

    // 1. The credential is genuine
    component cred = VerifyCredential(nAttrs);
    for (var i = 0; i < nAttrs; i++) {
        cred.attrs[i] <== attrs[i];
    }
    cred.R8x <== R8x;
    cred.R8y <== R8y;
    cred.S   <== S;
    cred.Ax  <== Ax;
    cred.Ay  <== Ay;

    // 2. Every predicate holds for that same credential
    component pred[nPreds];
    for (var p = 0; p < nPreds; p++) {
        pred[p] = Predicate(nAttrs);
        for (var i = 0; i < nAttrs; i++) {
            pred[p].attrs[i] <== attrs[i];
        }
        pred[p].attrIndex <== predAttr[p];
        pred[p].op        <== predOp[p];
        pred[p].value     <== predValue[p];
    }
}

component main {public [Ax, Ay, predAttr, predOp, predValue]} = Presentation(10, 4);
