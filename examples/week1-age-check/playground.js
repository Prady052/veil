const { buildPoseidon, buildEddsa } = require("circomlibjs");
const crypto = require("crypto");

// ---- Fixed lists (order must NEVER change; only append) ----
const STATES = ["MH", "KA", "DL", "TN", "GJ", "UP", "WB", "RJ", "KL", "TG"];
const INCOME_BANDS = ["<2.5L", "2.5L-5L", "5L-8L", "8L-12L", "12L+"]; // low -> high
const EMPLOYMENT = ["employed", "self-employed", "student", "unemployed", "retired"];

// Enum value = position + 1, so 0 can mean "absent"
function enumIndex(list, value) {
    const i = list.indexOf(value);
    if (i === -1) throw new Error(`Unknown value: ${value}`);
    return BigInt(i + 1);
}

function randomField(bytes) {
    return BigInt("0x" + crypto.randomBytes(bytes).toString("hex"));
}

async function main() {
    const poseidon = await buildPoseidon();
    const eddsa = await buildEddsa();
    const F = poseidon.F;

    // Text can't go straight into a circuit: pack bytes into numbers, then hash
    function encodeName(name) {
        const bytes = Buffer.from(name, "utf8");
        const chunks = [BigInt(bytes.length)];
        for (let i = 0; i < bytes.length; i += 31) {
            chunks.push(BigInt("0x" + bytes.subarray(i, i + 31).toString("hex")));
        }
        return F.toObject(poseidon(chunks));
    }

    // Holder's secret: only the wallet knows it (used in Week 4)
    const holderSecret = randomField(31);

    const attrs = [
        1n,                                   // 0 schemaVersion
        randomField(16),                      // 1 credentialId (128-bit)
        F.toObject(poseidon([holderSecret])), // 2 holderCommitment
        encodeName("Sameer Patil"),           // 3 name (hashed)
        19950314n,                            // 4 dateOfBirth YYYYMMDD
        enumIndex(STATES, "MH"),              // 5 state
        enumIndex(INCOME_BANDS, "5L-8L"),     // 6 incomeBand
        enumIndex(EMPLOYMENT, "employed"),    // 7 employmentStatus
        20261007n,                            // 8 issuedAt
        20311007n,                            // 9 expiresAt
    ];

    console.log("Attribute vector:");
    attrs.forEach((a, i) => console.log(`  [${i}]`, a.toString()));

    // Issuer signs ONE hash that covers all 10 attributes
    const privKey = crypto.randomBytes(32);
    const pubKey = eddsa.prv2pub(privKey);
    const msg = poseidon(attrs);
    const sig = eddsa.signPoseidon(privKey, msg);
    console.log("\nCredential hash M =", F.toObject(msg).toString());
    console.log("Valid?          ", eddsa.verifyPoseidon(msg, sig, pubKey));

    // Tamper: claim a lower income band to qualify for a scholarship
    const forged = [...attrs];
    forged[6] = enumIndex(INCOME_BANDS, "<2.5L");
    console.log("Forged valid?   ", eddsa.verifyPoseidon(poseidon(forged), sig, pubKey));
}

main();