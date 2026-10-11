pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";

// Picks attrs[index].
// RULE: index must be a real slot number (0 .. nAttrs-1).
template SelectAttribute(nAttrs) {
    signal input attrs[nAttrs];
    signal input index;
    signal output out;

    component isSlot[nAttrs];
    signal picked[nAttrs];
    var sum = 0;
    var hits = 0;

    for (var i = 0; i < nAttrs; i++) {
        // isSlot[i].out is 1 for the chosen slot and 0 for every other slot
        isSlot[i] = IsEqual();
        isSlot[i].in[0] <== index;
        isSlot[i].in[1] <== i;

        picked[i] <== isSlot[i].out * attrs[i];
        sum += picked[i];
        hits += isSlot[i].out;
    }

    hits === 1;     // exactly one slot matched, so index is valid
    out <== sum;    // every other slot contributed 0
}

// One predicate over one attribute. `op` chooses the comparison:
//   0  none   always true (an unused predicate slot)
//   1  ==     attr == value   (also how an attribute is disclosed)
//   2  >=     attr >= value
//   3  <=     attr <= value
template Predicate(nAttrs) {
    signal input attrs[nAttrs];
    signal input attrIndex;
    signal input op;
    signal input value;

    component sel = SelectAttribute(nAttrs);
    for (var i = 0; i < nAttrs; i++) {
        sel.attrs[i] <== attrs[i];
    }
    sel.index <== attrIndex;
    signal attr <== sel.out;

    // Which op was asked for?
    component isNone = IsEqual();
    isNone.in[0] <== op;
    isNone.in[1] <== 0;
    component isEq = IsEqual();
    isEq.in[0] <== op;
    isEq.in[1] <== 1;
    component isGe = IsEqual();
    isGe.in[0] <== op;
    isGe.in[1] <== 2;
    component isLe = IsEqual();
    isLe.in[0] <== op;
    isLe.in[1] <== 3;

    // RULE: op is one of 0, 1, 2, 3
    isNone.out + isEq.out + isGe.out + isLe.out === 1;

    // ---- attr == value ----
    component eq = IsEqual();
    eq.in[0] <== attr;
    eq.in[1] <== value;

    // ---- attr >= value, attr <= value ----
    // Comparators are only correct for 32-bit numbers. For >= and <= both sides
    // must fit in 32 bits. For the other ops they are replaced by 0, so that
    // hashes (name, holderCommitment) can still be used with ==.
    signal isRange <== isGe.out + isLe.out;
    signal a <== isRange * attr;
    signal b <== isRange * value;

    component aBits = Num2Bits(32);
    aBits.in <== a;
    component bBits = Num2Bits(32);
    bBits.in <== b;

    component ge = GreaterEqThan(32);
    ge.in[0] <== a;
    ge.in[1] <== b;
    component le = LessEqThan(32);
    le.in[0] <== a;
    le.in[1] <== b;

    // RULE: the comparison that was asked for must be true
    signal okEq <== isEq.out * eq.out;
    signal okGe <== isGe.out * ge.out;
    signal okLe <== isLe.out * le.out;
    isNone.out + okEq + okGe + okLe === 1;
}
