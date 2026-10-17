// Shared pieces of a presentation: used by the holder (to prove) and the verifier (to check).
import type { PublicKey } from "./did";
import { encodeText, randomField, toField } from "./encoding";
import { encodePredicates, type EncodedPredicates, type Predicate } from "./predicates";
import type { VerifiableCredential } from "./vc";

// What a verifier wants proven, before it is turned into one request
export interface RequestTemplate {
    issuer: string;           // the issuer DID the verifier trusts
    predicates: Predicate[];
    pseudonym?: boolean;      // true asks the holder to reveal their pseudonym for this domain
}

// A request for one presentation, as the verifier sends it
export interface PresentationRequest {
    issuer: string;
    domain: string;           // the verifier's own domain name
    nonce: string;            // fresh random number: a proof can only answer this one request
    pseudonym: boolean;
    predicates: Predicate[];
}

// A Groth16 proof as snarkjs produces it
export interface Groth16Proof {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
}

// What the holder sends back. No attributes, no signature.
export interface Presentation {
    verificationMethod: string; // which issuer key signed the credential
    proof: Groth16Proof;
    pseudonym?: string;         // only when the request asked for one
}

// Everything the circuit takes, private and public
export interface CircuitInput extends EncodedPredicates {
    // private
    attrs: string[];
    R8x: string;
    R8y: string;
    S: string;
    holderSecret: string;
    // public
    Ax: string;
    Ay: string;
    nonce: string;
    domainHash: string;
    wantPseudonym: string;
}

// HOLDER: check a request that arrived from outside (pasted, scanned, fetched) before using it.
// TypeScript's types only exist while writing code; they can't check data that arrives while
// the program runs, so every field is checked here. Throws an Error that explains the problem.
export function parseRequest(data: unknown): PresentationRequest {
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
        throw new Error("A request must be a JSON object");
    }
    const r = data as Record<string, unknown>;
    const text = (field: string): string => {
        const value = r[field];
        if (typeof value !== "string" || value === "") {
            throw new Error(`The request's "${field}" must be a non-empty string`);
        }
        return value;
    };

    const issuer = text("issuer");
    if (!issuer.startsWith("did:web:")) throw new Error(`The request's issuer is not a did:web: ${issuer}`);
    const domain = text("domain");
    const nonce = text("nonce");
    toField(nonce, "The request's nonce");

    const pseudonym = r.pseudonym ?? false;
    if (typeof pseudonym !== "boolean") throw new Error(`The request's "pseudonym" must be true or false`);

    if (!Array.isArray(r.predicates)) throw new Error(`The request's "predicates" must be a list`);
    for (const p of r.predicates) {
        const value = (p as Record<string, unknown>)?.value;
        const isText = typeof value === "string";
        const isList = Array.isArray(value) && value.every((v) => typeof v === "string");
        if (typeof p !== "object" || p === null || (!isText && !isList)) {
            throw new Error("Each predicate needs an attr, an op and a value");
        }
    }
    const predicates = r.predicates as Predicate[];
    encodePredicates(predicates); // throws on unknown attributes, operators or values

    return { issuer, domain, nonce, pseudonym, predicates };
}

// VERIFIER: turn "what I want proven" into a request for one presentation
export function newRequest(template: RequestTemplate, domain: string): PresentationRequest {
    return {
        issuer: template.issuer,
        domain,
        nonce: randomField().toString(),
        pseudonym: template.pseudonym ?? false,
        predicates: template.predicates,
    };
}

// The request's public inputs, shared by both sides so they always agree
function requestInputs(request: PresentationRequest) {
    return {
        nonce: request.nonce,
        domainHash: encodeText(request.domain).toString(),
        wantPseudonym: request.pseudonym ? "1" : "0",
        ...encodePredicates(request.predicates),
    };
}

// HOLDER: everything the circuit needs, private and public
export function buildCircuitInput(
    vc: Pick<VerifiableCredential, "proof">,
    issuerKey: PublicKey,
    request: PresentationRequest,
    holderSecret: string,
): CircuitInput {
    return {
        attrs: vc.proof.attributes,
        R8x: vc.proof.signature.R8x,
        R8y: vc.proof.signature.R8y,
        S: vc.proof.signature.S,
        holderSecret,
        Ax: issuerKey.x,
        Ay: issuerKey.y,
        ...requestInputs(request),
    };
}

// VERIFIER: the public signals, built from its own request and the issuer's key.
// The pseudonym is the one value that comes from the holder: the verifier can't compute it,
// but the proof only verifies if it is the true one. If none was asked for, it must be 0.
//
// Order: the circuit's output first, then its public inputs in the order they are declared in
// circuits/presentation.circom:
//   pseudonym, Ax, Ay, nonce, domainHash, wantPseudonym,
//   predAttr[], predOp[], predValue[], predSet[][] (row by row).
export function buildPublicSignals(
    issuerKey: PublicKey,
    request: PresentationRequest,
    pseudonym?: string,
): string[] {
    const { nonce, domainHash, wantPseudonym, predAttr, predOp, predValue, predSet } = requestInputs(request);
    return [
        request.pseudonym ? String(pseudonym) : "0",
        issuerKey.x, issuerKey.y, nonce, domainHash, wantPseudonym,
        ...predAttr, ...predOp, ...predValue, ...predSet.flat(),
    ];
}
