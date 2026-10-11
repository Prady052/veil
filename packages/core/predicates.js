// Predicates: what a verifier asks a holder to prove about the credential.
//   { attr: "dateOfBirth", op: "<=", value: "2008-10-11" }
const { ATTRIBUTES, encodeValue } = require("./encoding");

// Must match Presentation(10, 4) in circuits/presentation.circom
const N_PREDICATES = 4;

// Operator codes, as the circuit understands them (see circuits/lib/predicate.circom)
const OPS = { "==": 1, ">=": 2, "<=": 3 };
const OP_NONE = 0;

// Readable predicates -> the circuit's three public input arrays,
// padded with "no predicate" up to N_PREDICATES.
async function encodePredicates(predicates) {
    if (predicates.length > N_PREDICATES) {
        throw new Error(`At most ${N_PREDICATES} predicates are supported`);
    }

    const predAttr = [];
    const predOp = [];
    const predValue = [];

    for (const p of predicates) {
        const slot = ATTRIBUTES.indexOf(p.attr);
        if (slot === -1) throw new Error(`Unknown attribute: ${p.attr}`);
        if (!Object.hasOwn(OPS, p.op)) throw new Error(`Unknown operator: ${p.op}`);

        predAttr.push(String(slot));
        predOp.push(String(OPS[p.op]));
        predValue.push((await encodeValue(p.attr, p.value)).toString());
    }

    while (predAttr.length < N_PREDICATES) {
        predAttr.push("0");
        predOp.push(String(OP_NONE));
        predValue.push("0");
    }

    return { predAttr, predOp, predValue };
}

module.exports = { N_PREDICATES, OPS, OP_NONE, encodePredicates };
