pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";

template AgeCheck() {
    signal input dob;     // private: only the holder knows it
    signal input today;   // public: the verifier chooses it

    // 1. Range checks: comparators are only correct for 32-bit inputs
    component dobBits = Num2Bits(32);
    dobBits.in <== dob;

    component todayBits = Num2Bits(32);
    todayBits.in <== today;

    // 2. Threshold = today minus 18 years
    signal threshold;
    threshold <== today - 180000;

    // Also range-check the threshold: if today < 180000 the subtraction
    // would wrap around to ~p, and the comparison below would be meaningless
    component thresholdBits = Num2Bits(32);
    thresholdBits.in <== threshold;

    // 3. The actual rule: dob <= threshold
    component le = LessEqThan(32);
    le.in[0] <== dob;
    le.in[1] <== threshold;
    le.out === 1;
}

component main {public [today]} = AgeCheck();