// Shared pieces of a presentation: used by the holder (to prove) and the verifier (to check).
//
// A request, as the verifier sends it:
//   { issuer, domain, nonce, pseudonym, predicates }
// `pseudonym: true` asks the holder to reveal their pseudonym for this domain.
const crypto = require("crypto");
const { didToUrl, publicKeyFromDidDocument } = require("./did");
const { encodeText } = require("./encoding");
const { encodePredicates } = require("./predicates");

// Fetch an issuer's DID document and return one of its public keys.
// keyId is the full key name, e.g. "did:web:localhost%3A3000#key-1".
async function resolveIssuerKey(did, keyId) {
    const response = await fetch(didToUrl(did));
    if (!response.ok) throw new Error(`Could not resolve ${did}: HTTP ${response.status}`);
    const didDocument = await response.json();
    if (didDocument.id !== did) throw new Error("DID document is for a different DID");
    return publicKeyFromDidDocument(didDocument, keyId);
}

// VERIFIER: turn "what I want proven" into a request for one presentation.
// The nonce is fresh random for every request, so a proof can only answer this one.
function newRequest({ issuer, predicates, pseudonym = false }, domain) {
    return {
        issuer,
        domain,
        nonce: BigInt("0x" + crypto.randomBytes(31).toString("hex")).toString(),
        pseudonym,
        predicates,
    };
}

// The request's public inputs, shared by both sides so they always agree
async function requestInputs(request) {
    return {
        nonce: request.nonce,
        domainHash: (await encodeText(request.domain)).toString(),
        wantPseudonym: request.pseudonym ? "1" : "0",
        ...(await encodePredicates(request.predicates)),
    };
}

// HOLDER: everything the circuit needs, private and public
async function buildCircuitInput(vc, issuerKey, request, holderSecret) {
    return {
        // private
        attrs: vc.proof.attributes,
        R8x: vc.proof.signature.R8x,
        R8y: vc.proof.signature.R8y,
        S: vc.proof.signature.S,
        holderSecret,
        // public
        Ax: issuerKey.x,
        Ay: issuerKey.y,
        ...(await requestInputs(request)),
    };
}

// VERIFIER: the public signals, built from its own request and the issuer's key.
// The pseudonym is the one value that comes from the holder: the verifier can't compute it,
// but the proof only verifies if it is the true one. If none was asked for, it must be 0.
//
// Order: the circuit's output first, then its public inputs in the order they are declared in
// circuits/presentation.circom:
//   pseudonym, Ax, Ay, nonce, domainHash, wantPseudonym, predAttr[], predOp[], predValue[].
async function buildPublicSignals(issuerKey, request, pseudonym) {
    const { nonce, domainHash, wantPseudonym, predAttr, predOp, predValue } = await requestInputs(request);
    return [
        request.pseudonym ? String(pseudonym) : "0",
        issuerKey.x, issuerKey.y, nonce, domainHash, wantPseudonym,
        ...predAttr, ...predOp, ...predValue,
    ];
}

module.exports = { resolveIssuerKey, newRequest, buildCircuitInput, buildPublicSignals };
