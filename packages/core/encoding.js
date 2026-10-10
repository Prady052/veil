const { buildPoseidon } = require("circomlibjs");

// ---- Fixed lists: see docs/encoding.md. Append-only, never reorder ----
const SCHEMA_VERSION = 1n;
const STATES = ["MH", "KA", "DL", "TN", "GJ", "UP", "WB", "RJ", "KL", "TG"];
const INCOME_BANDS = ["<2.5L", "2.5L-5L", "5L-8L", "8L-12L", "12L+"]; // low -> high
const EMPLOYMENT = ["employed", "self-employed", "student", "unemployed", "retired"];

// Build Poseidon once and reuse it (building is slow)
let poseidonPromise;
function getPoseidon() {
    if (!poseidonPromise) poseidonPromise = buildPoseidon();
    return poseidonPromise;
}

// Enum value = position + 1, so 0 can mean "absent"
function enumIndex(list, value) {
    const i = list.indexOf(value);
    if (i === -1) throw new Error(`Unknown value: ${value}`);
    return BigInt(i + 1);
}

// "1995-03-14" -> 19950314n
function dateToInt(iso) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(iso)) throw new Error(`Bad date: ${iso}`);
    return BigInt(iso.replace(/-/g, ""));
}

// Text -> one field element: pack 31 bytes per chunk, length first, then hash
async function encodeName(name) {
    const poseidon = await getPoseidon();
    const bytes = Buffer.from(name, "utf8");
    const chunks = [BigInt(bytes.length)];
    for (let i = 0; i < bytes.length; i += 31) {
        chunks.push(BigInt("0x" + bytes.subarray(i, i + 31).toString("hex")));
    }
    return poseidon.F.toObject(poseidon(chunks));
}

// Human-readable claims -> the 10-slot attribute vector
async function encodeAttributes(c) {
    return [
        SCHEMA_VERSION,                           // 0
        BigInt(c.credentialId),                   // 1
        BigInt(c.holderCommitment),               // 2
        await encodeName(c.name),                 // 3
        dateToInt(c.dateOfBirth),                 // 4
        enumIndex(STATES, c.state),               // 5
        enumIndex(INCOME_BANDS, c.incomeBand),    // 6
        enumIndex(EMPLOYMENT, c.employmentStatus),// 7
        dateToInt(c.issuedAt),                    // 8
        dateToInt(c.expiresAt),                   // 9
    ];
}

// The single number the issuer signs: M = Poseidon(attr[0..9])
async function hashAttributes(attrs) {
    const poseidon = await getPoseidon();
    return poseidon.F.toObject(poseidon(attrs));
}

module.exports = {
    SCHEMA_VERSION, STATES, INCOME_BANDS, EMPLOYMENT,
    dateToInt, encodeName, encodeAttributes, hashAttributes,
};
