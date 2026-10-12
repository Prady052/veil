// Shared pieces of a presentation: used by the holder (to prove) and the verifier (to check).
//
// A request, as the verifier sends it:
//   { issuer, domain, nonce, predicates }
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
function newRequest({ issuer, predicates }, domain) {
    return {
        issuer,
        domain,
        nonce: BigInt("0x" + crypto.randomBytes(31).toString("hex")).toString(),
        predicates,
    };
}

// The request's public inputs, shared by both sides so they always agree
async function requestInputs(request) {
    return {
        nonce: request.nonce,
        domainHash: (await encodeText(request.domain)).toString(),
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

// VERIFIER: the public inputs, built from its own request and the issuer's key.
// The order must match the order the public inputs are declared in
// circuits/presentation.circom: Ax, Ay, nonce, domainHash, predAttr[], predOp[], predValue[].
async function buildPublicSignals(issuerKey, request) {
    const { nonce, domainHash, predAttr, predOp, predValue } = await requestInputs(request);
    return [issuerKey.x, issuerKey.y, nonce, domainHash, ...predAttr, ...predOp, ...predValue];
}

module.exports = { resolveIssuerKey, newRequest, buildCircuitInput, buildPublicSignals };
