// Predicates: what a verifier asks a holder to prove about the credential.
//   { attr: "dateOfBirth", op: "<=", value: "2008-10-11" }
//   { attr: "state",       op: "in", value: ["MH", "KA"] }
const { ATTRIBUTES, encodeValue } = require("./encoding");

// Must match Presentation(10, 4, 4) in circuits/presentation.circom
const N_PREDICATES = 4;
const SET_SIZE = 4; // most values an "in" predicate can list

// Operator codes, as the circuit understands them (see circuits/lib/predicate.circom)
const OPS = { "==": 1, ">=": 2, "<=": 3, "in": 4 };
const OP_NONE = 0;

// The allowed values of an "in" predicate, as exactly SET_SIZE field elements.
// A short list is padded by repeating its first value. It is never padded with 0:
// 0 means "attribute absent", so a 0 in the set would let an absent attribute pass.
async function encodeSet(attr, values) {
    if (!Array.isArray(values) || values.length === 0) {
        throw new Error(`"in" needs a list of 1 to ${SET_SIZE} values`);
    }
    if (values.length > SET_SIZE) {
        throw new Error(`"in" supports at most ${SET_SIZE} values`);
    }
    const set = [];
    for (const value of values) {
        set.push((await encodeValue(attr, value)).toString());
    }
    while (set.length < SET_SIZE) set.push(set[0]);
    return set;
}

// Readable predicates -> the circuit's public input arrays,
// padded with "no predicate" up to N_PREDICATES.
async function encodePredicates(predicates) {
    if (predicates.length > N_PREDICATES) {
        throw new Error(`At most ${N_PREDICATES} predicates are supported`);
    }

    const predAttr = [];
    const predOp = [];
    const predValue = [];
    const predSet = [];
    const emptySet = () => new Array(SET_SIZE).fill("0"); // ignored unless the op is "in"

    for (const p of predicates) {
        const slot = ATTRIBUTES.indexOf(p.attr);
        if (slot === -1) throw new Error(`Unknown attribute: ${p.attr}`);
        if (!Object.hasOwn(OPS, p.op)) throw new Error(`Unknown operator: ${p.op}`);

        predAttr.push(String(slot));
        predOp.push(String(OPS[p.op]));
        if (p.op === "in") {
            predValue.push("0");
            predSet.push(await encodeSet(p.attr, p.value));
        } else {
            predValue.push((await encodeValue(p.attr, p.value)).toString());
            predSet.push(emptySet());
        }
    }

    while (predAttr.length < N_PREDICATES) {
        predAttr.push("0");
        predOp.push(String(OP_NONE));
        predValue.push("0");
        predSet.push(emptySet());
    }

    return { predAttr, predOp, predValue, predSet };
}

module.exports = { N_PREDICATES, SET_SIZE, OPS, OP_NONE, encodePredicates };
