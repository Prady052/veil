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
    // Reject dates that don't exist, like 1995-02-30 or 1995-13-01
    const d = new Date(iso + "T00:00:00Z");
    if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== iso) {
        throw new Error(`Bad date: ${iso}`);
    }
    return BigInt(iso.replace(/-/g, ""));
}

// The BN254 scalar field prime p: every circuit value must be below it
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Decimal string -> field element, refusing anything that would wrap around mod p
function toField(value, label) {
    if (!/^\d+$/.test(String(value))) throw new Error(`${label} must be a decimal number`);
    const n = BigInt(value);
    if (n >= FIELD_PRIME) throw new Error(`${label} is not a valid field element`);
    return n;
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

// The attribute vector's slot order: ATTRIBUTES[4] is "dateOfBirth", and so on
const ATTRIBUTES = [
    "schemaVersion",    // 0
    "credentialId",     // 1
    "holderCommitment", // 2
    "name",             // 3
    "dateOfBirth",      // 4
    "state",            // 5
    "incomeBand",       // 6
    "employmentStatus", // 7
    "issuedAt",         // 8
    "expiresAt",        // 9
];

// Encode ONE attribute value as its field element.
// Used for the credential itself and for the values in predicates, so they always agree.
async function encodeValue(attr, value) {
    switch (attr) {
        case "schemaVersion":
        case "credentialId":
        case "holderCommitment":
            return toField(value, attr);
        case "name":
            return encodeName(value);
        case "dateOfBirth":
        case "issuedAt":
        case "expiresAt":
            return dateToInt(value);
        case "state":
            return enumIndex(STATES, value);
        case "incomeBand":
            return enumIndex(INCOME_BANDS, value);
        case "employmentStatus":
            return enumIndex(EMPLOYMENT, value);
        default:
            throw new Error(`Unknown attribute: ${attr}`);
    }
}

// Human-readable claims -> the 10-slot attribute vector
async function encodeAttributes(c) {
    const claims = { ...c, schemaVersion: SCHEMA_VERSION.toString() };
    const attrs = [];
    for (const attr of ATTRIBUTES) {
        attrs.push(await encodeValue(attr, claims[attr]));
    }
    return attrs;
}

// The single number the issuer signs: M = Poseidon(attr[0..9])
async function hashAttributes(attrs) {
    const poseidon = await getPoseidon();
    return poseidon.F.toObject(poseidon(attrs));
}

module.exports = {
    SCHEMA_VERSION, STATES, INCOME_BANDS, EMPLOYMENT, ATTRIBUTES,
    dateToInt, encodeName, encodeValue, encodeAttributes, hashAttributes,
};
