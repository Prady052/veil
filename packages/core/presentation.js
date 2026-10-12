// Shared pieces of a presentation: used by the holder (to prove) and the verifier (to check).
const { didToUrl, publicKeyFromDidDocument } = require("./did");
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

// HOLDER: everything the circuit needs, private and public
async function buildCircuitInput(vc, issuerKey, predicates, holderSecret) {
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
        ...(await encodePredicates(predicates)),
    };
}

// VERIFIER: the public inputs, built from its own request and the issuer's key.
// The order must match the order the public inputs are declared in
// circuits/presentation.circom: Ax, Ay, predAttr[], predOp[], predValue[].
async function buildPublicSignals(issuerKey, predicates) {
    const { predAttr, predOp, predValue } = await encodePredicates(predicates);
    return [issuerKey.x, issuerKey.y, ...predAttr, ...predOp, ...predValue];
}

module.exports = { resolveIssuerKey, buildCircuitInput, buildPublicSignals };
