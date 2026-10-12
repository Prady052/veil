// Predicates: what a verifier asks a holder to prove about the credential.
//   { attr: "dateOfBirth", op: "<=", value: "2008-10-11" }
//   { attr: "state",       op: "in", value: ["MH", "KA"] }
import { ATTRIBUTES, encodeValue } from "./encoding";

export type Operator = "==" | ">=" | "<=" | "in";

export interface Predicate {
    attr: string;
    op: Operator;
    value: string | string[]; // a list for "in", a single value otherwise
}

// The predicates as the circuit's public inputs
export interface EncodedPredicates {
    predAttr: string[];
    predOp: string[];
    predValue: string[];
    predSet: string[][];
}

// Must match Presentation(10, 4, 4) in circuits/presentation.circom
export const N_PREDICATES = 4;
export const SET_SIZE = 4; // most values an "in" predicate can list

// Operator codes, as the circuit understands them (see circuits/lib/predicate.circom)
export const OPS: Record<Operator, number> = { "==": 1, ">=": 2, "<=": 3, "in": 4 };
export const OP_NONE = 0;

// The allowed values of an "in" predicate, as exactly SET_SIZE field elements.
// A short list is padded by repeating its first value. It is never padded with 0:
// 0 means "attribute absent", so a 0 in the set would let an absent attribute pass.
function encodeSet(attr: string, values: string | string[]): string[] {
    if (!Array.isArray(values) || values.length === 0) {
        throw new Error(`"in" needs a list of 1 to ${SET_SIZE} values`);
    }
    if (values.length > SET_SIZE) {
        throw new Error(`"in" supports at most ${SET_SIZE} values`);
    }
    const set = values.map((value) => encodeValue(attr, value).toString());
    while (set.length < SET_SIZE) set.push(set[0]);
    return set;
}

// Readable predicates -> the circuit's public input arrays,
// padded with "no predicate" up to N_PREDICATES.
export function encodePredicates(predicates: Predicate[]): EncodedPredicates {
    if (predicates.length > N_PREDICATES) {
        throw new Error(`At most ${N_PREDICATES} predicates are supported`);
    }

    const predAttr: string[] = [];
    const predOp: string[] = [];
    const predValue: string[] = [];
    const predSet: string[][] = [];
    const emptySet = () => new Array<string>(SET_SIZE).fill("0"); // ignored unless the op is "in"

    for (const p of predicates) {
        const slot = (ATTRIBUTES as readonly string[]).indexOf(p.attr);
        if (slot === -1) throw new Error(`Unknown attribute: ${p.attr}`);
        if (!Object.hasOwn(OPS, p.op)) throw new Error(`Unknown operator: ${p.op}`);

        predAttr.push(String(slot));
        predOp.push(String(OPS[p.op]));
        if (p.op === "in") {
            predValue.push("0");
            predSet.push(encodeSet(p.attr, p.value));
        } else {
            if (Array.isArray(p.value)) throw new Error(`"${p.op}" takes a single value`);
            predValue.push(encodeValue(p.attr, p.value).toString());
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
