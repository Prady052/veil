// Helpers for did:web, shared by the issuer (publishes the document)
// and the wallet and verifiers (resolve it). Runs in Node and in the browser.

// A BabyJubJub public key, as the decimal strings the circuit takes
export interface PublicKey {
    x: string;
    y: string;
}

export interface VerificationMethod {
    id: string;
    type: string;
    controller: string;
    publicKeyJwk: { kty: string; crv: string; x: string; y: string };
}

export interface DidDocument {
    "@context": string[];
    id: string;
    verificationMethod: VerificationMethod[];
    assertionMethod: string[];
}

// Field element <-> base64url of 32 big-endian bytes: the JWK convention for key coordinates
export function toBase64Url(n: string | bigint): string {
    const hex = BigInt(n).toString(16).padStart(64, "0");
    let binary = "";
    for (let i = 0; i < hex.length; i += 2) {
        binary += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(s: string): string {
    const base64 = s.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
    let hex = "";
    for (let i = 0; i < binary.length; i++) {
        hex += binary.charCodeAt(i).toString(16).padStart(2, "0");
    }
    return BigInt("0x" + hex).toString();
}

// "localhost:3000" -> "did:web:localhost%3A3000"
// The port's ":" must be percent-encoded, because ":" separates the parts of a DID
export function didFromHost(host: string): string {
    return "did:web:" + encodeURIComponent(host);
}

// "did:web:localhost%3A3000" -> "http://localhost:3000/.well-known/did.json"
export function didToUrl(did: string): string {
    if (!did.startsWith("did:web:")) throw new Error(`Not a did:web: ${did}`);
    const parts = did.slice("did:web:".length).split(":").map(decodeURIComponent);
    const host = parts[0];
    const dir = parts.length > 1 ? "/" + parts.slice(1).join("/") : "/.well-known";
    // did:web requires https; plain http is allowed only for local development
    const scheme = /^(localhost|127\.0\.0\.1)(:|$)/.test(host) ? "http" : "https";
    return `${scheme}://${host}${dir}/did.json`;
}

// The DID document: "this DID is controlled by this BabyJubJub public key"
export function buildDidDocument(did: string, publicKey: PublicKey): DidDocument {
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

// Pull one public key out of a DID document.
// keyId is the full name, e.g. "did:web:localhost%3A3000#key-1".
export function publicKeyFromDidDocument(doc: DidDocument, keyId: string): PublicKey {
    const method = (doc.verificationMethod || []).find((m) => m.id === keyId);
    if (!method) throw new Error(`Key not found in DID document: ${keyId}`);
    if (method.controller !== doc.id) throw new Error("Key is not controlled by this DID");
    // The key must be listed as allowed to sign credentials
    if (!(doc.assertionMethod || []).includes(keyId)) {
        throw new Error("Key is not authorised to sign credentials");
    }
    const jwk = method.publicKeyJwk;
    if (!jwk || jwk.crv !== "BabyJubJub") throw new Error("Not a BabyJubJub key");
    return { x: fromBase64Url(jwk.x), y: fromBase64Url(jwk.y) };
}

// Fetch an issuer's DID document and return one of its public keys
export async function resolveIssuerKey(did: string, keyId: string): Promise<PublicKey> {
    const url = didToUrl(did);
    let response: Response;
    try {
        response = await fetch(url);
    } catch {
        throw new Error(`Could not reach the issuer at ${url}. Is it running?`);
    }
    if (!response.ok) throw new Error(`Could not resolve ${did}: HTTP ${response.status}`);
    const didDocument = (await response.json()) as DidDocument;
    if (didDocument.id !== did) throw new Error("DID document is for a different DID");
    return publicKeyFromDidDocument(didDocument, keyId);
}
