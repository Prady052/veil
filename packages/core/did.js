// Helpers for did:web, shared by the issuer (publishes the document)
// and later the wallet and verifiers (resolve it).

// Field element <-> base64url of 32 big-endian bytes: the JWK convention for key coordinates
function toBase64Url(n) {
    const hex = BigInt(n).toString(16).padStart(64, "0");
    return Buffer.from(hex, "hex").toString("base64url");
}

function fromBase64Url(s) {
    return BigInt("0x" + Buffer.from(s, "base64url").toString("hex")).toString();
}

// "localhost:3000" -> "did:web:localhost%3A3000"
// The port's ":" must be percent-encoded, because ":" separates the parts of a DID
function didFromHost(host) {
    return "did:web:" + encodeURIComponent(host);
}

// "did:web:localhost%3A3000" -> "http://localhost:3000/.well-known/did.json"
function didToUrl(did) {
    if (!did.startsWith("did:web:")) throw new Error(`Not a did:web: ${did}`);
    const parts = did.slice("did:web:".length).split(":").map(decodeURIComponent);
    const host = parts[0];
    const dir = parts.length > 1 ? "/" + parts.slice(1).join("/") : "/.well-known";
    // did:web requires https; plain http is allowed only for local development
    const scheme = /^(localhost|127\.0\.0\.1)(:|$)/.test(host) ? "http" : "https";
    return `${scheme}://${host}${dir}/did.json`;
}

// The DID document: "this DID is controlled by this BabyJubJub public key"
function buildDidDocument(did, publicKey) {
    const keyId = `${did}#key-1`;
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/jwk/v1",
        ],
        id: did,
        verificationMethod: [
            {
                id: keyId,
                type: "JsonWebKey",
                controller: did,
                publicKeyJwk: {
                    kty: "EC",
                    crv: "BabyJubJub", // not a registered JWK curve: Veil's custom proof type
                    x: toBase64Url(publicKey.x),
                    y: toBase64Url(publicKey.y),
                },
            },
        ],
        // "assertionMethod" = this key is allowed to sign credentials
        assertionMethod: [keyId],
    };
}

module.exports = { toBase64Url, fromBase64Url, didFromHost, didToUrl, buildDidDocument };
