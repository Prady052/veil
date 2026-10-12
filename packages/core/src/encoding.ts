// How claims become field elements. See docs/encoding.md.
// This module runs in Node and in the browser: no Buffer, no fs, no Node crypto.
import * as poseidonLite from "poseidon-lite";

// ---- Fixed lists: append-only, never reorder ----
export const SCHEMA_VERSION = 1n;
export const STATES = ["MH", "KA", "DL", "TN", "GJ", "UP", "WB", "RJ", "KL", "TG"] as const;
export const INCOME_BANDS = ["<2.5L", "2.5L-5L", "5L-8L", "8L-12L", "12L+"] as const; // low -> high
export const EMPLOYMENT = ["employed", "self-employed", "student", "unemployed", "retired"] as const;

// The attribute vector's slot order: ATTRIBUTES[4] is "dateOfBirth", and so on
export const ATTRIBUTES = [
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
] as const;

export type AttributeName = (typeof ATTRIBUTES)[number];

// The readable claims of one credential. schemaVersion is added by encodeAttributes.
export type Claims = Record<Exclude<AttributeName, "schemaVersion">, string>;

// The BN254 scalar field prime p: every circuit value must be below it
export const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Poseidon over 1 to 16 field elements. Gives the same result as circomlib's Poseidon(n).
export function poseidon(inputs: bigint[]): bigint {
    const hashers = poseidonLite as unknown as Record<string, ((inputs: bigint[]) => bigint) | undefined>;
    const hash = hashers[`poseidon${inputs.length}`];
    if (!hash) throw new Error(`Poseidon takes 1 to 16 inputs, got ${inputs.length}`);
    return hash(inputs);
}

// A random number that is safely below p (31 bytes = 248 bits)
export function randomField(byteLength = 31): bigint {
    const bytes = new Uint8Array(byteLength);
    globalThis.crypto.getRandomValues(bytes);
    return bytesToBigInt(bytes);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
    let hex = "";
    for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
    return hex === "" ? 0n : BigInt("0x" + hex);
}

// Enum value = position + 1, so 0 can mean "absent"
function enumIndex(list: readonly string[], value: string): bigint {
    const i = list.indexOf(value);
    if (i === -1) throw new Error(`Unknown value: ${value}`);
    return BigInt(i + 1);
}

// "1995-03-14" -> 19950314n
export function dateToInt(iso: string): bigint {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(iso)) throw new Error(`Bad date: ${iso}`);
    // Reject dates that don't exist, like 1995-02-30 or 1995-13-01
    const d = new Date(iso + "T00:00:00Z");
    if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== iso) {
        throw new Error(`Bad date: ${iso}`);
    }
    return BigInt(iso.replace(/-/g, ""));
}

// Decimal string -> field element, refusing anything that would wrap around mod p
export function toField(value: string | bigint, label: string): bigint {
    if (!/^\d+$/.test(String(value))) throw new Error(`${label} must be a decimal number`);
    const n = BigInt(value);
    if (n >= FIELD_PRIME) throw new Error(`${label} is not a valid field element`);
    return n;
}

// Text -> one field element: pack 31 bytes per chunk, length first, then hash.
// Used for the name attribute and for a verifier's domain name.
export function encodeText(text: string): bigint {
    const bytes = new TextEncoder().encode(text);
    const chunks: bigint[] = [BigInt(bytes.length)];
    for (let i = 0; i < bytes.length; i += 31) {
        chunks.push(bytesToBigInt(bytes.subarray(i, i + 31)));
    }
    if (chunks.length > 16) throw new Error("Text is too long to encode (465 bytes at most)");
    return poseidon(chunks);
}

// The holder commitment the issuer signs: a one-way fingerprint of the wallet's secret
export function holderCommitment(holderSecret: string | bigint): bigint {
    return poseidon([BigInt(holderSecret)]);
}

// Encode ONE attribute value as its field element.
// Used for the credential itself and for the values in predicates, so they always agree.
export function encodeValue(attr: string, value: string): bigint {
    switch (attr) {
        case "schemaVersion":
        case "credentialId":
        case "holderCommitment":
            return toField(value, attr);
        case "name":
            return encodeText(value);
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
export function encodeAttributes(claims: Claims): bigint[] {
    const all: Record<AttributeName, string> = { ...claims, schemaVersion: SCHEMA_VERSION.toString() };
    return ATTRIBUTES.map((attr) => encodeValue(attr, all[attr]));
}

// The single number the issuer signs: M = Poseidon(attr[0..9])
export function hashAttributes(attrs: bigint[]): bigint {
    return poseidon(attrs);
}
