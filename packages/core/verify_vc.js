// Check a Veil credential the way a wallet would right after receiving it:
// resolve the issuer's DID, fetch its public key, and verify the signature.
const { buildEddsa } = require("circomlibjs");
const fs = require("fs");
const { didToUrl, publicKeyFromDidDocument } = require("./did");
const { encodeAttributes, hashAttributes } = require("./encoding");
const { PROOF_TYPE, claimsFromVc } = require("./vc");

// Returns { ok, checks: [{ name, ok, detail }] }. Stops at the first failed check.
async function verifyVc(vc, now = new Date()) {
    const checks = [];
    const pass = (name, detail = "") => checks.push({ name, ok: true, detail });
    const fail = (name, detail) => {
        checks.push({ name, ok: false, detail });
        return { ok: false, checks };
    };

    // 1. Is this the kind of credential we understand?
    if (!vc.proof || vc.proof.type !== PROOF_TYPE) {
        return fail("Proof type", `expected ${PROOF_TYPE}`);
    }
    pass("Proof type", PROOF_TYPE);

    // 2. Resolve the issuer's DID: fetch did.json from the issuer's website
    let didDocument;
    const url = didToUrl(vc.issuer);
    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        didDocument = await response.json();
    } catch (err) {
        return fail("Resolve DID", `${url}: ${err.message}`);
    }
    if (didDocument.id !== vc.issuer) {
        return fail("Resolve DID", "document is for a different DID");
    }
    pass("Resolve DID", url);

    // 3. Get the signing key the credential points to
    let publicKey;
    try {
        if (!vc.proof.verificationMethod.startsWith(vc.issuer + "#")) {
            throw new Error("key does not belong to the issuer");
        }
        publicKey = publicKeyFromDidDocument(didDocument, vc.proof.verificationMethod);
    } catch (err) {
        return fail("Issuer key", err.message);
    }
    pass("Issuer key", vc.proof.verificationMethod);

    // 4. Do the readable claims match the 10 signed numbers?
    //    We re-encode the claims ourselves and compare.
    let attrs;
    try {
        attrs = await encodeAttributes(claimsFromVc(vc));
    } catch (err) {
        return fail("Claims match attributes", err.message);
    }
    const signedAttrs = vc.proof.attributes || [];
    const sameAttrs = attrs.length === signedAttrs.length
        && attrs.every((a, i) => a.toString() === signedAttrs[i]);
    if (!sameAttrs) {
        return fail("Claims match attributes", "readable claims differ from the attribute vector");
    }
    pass("Claims match attributes");

    // 5. Is the issuer's signature valid for M = Poseidon(attributes)?
    const eddsa = await buildEddsa();
    const F = eddsa.babyJub.F;
    const M = await hashAttributes(attrs);
    let signatureOk = false;
    try {
        const sig = vc.proof.signature;
        signatureOk = eddsa.verifyPoseidon(
            F.e(M),
            { R8: [F.e(sig.R8x), F.e(sig.R8y)], S: BigInt(sig.S) },
            [F.e(publicKey.x), F.e(publicKey.y)],
        );
    } catch (err) {
        return fail("Signature", err.message);
    }
    if (!signatureOk) return fail("Signature", "not signed by the issuer's key");
    pass("Signature");

    // 6. Is the credential inside its validity period?
    if (now < new Date(vc.validFrom) || now > new Date(vc.validUntil)) {
        return fail("Validity period", `${vc.validFrom} to ${vc.validUntil}`);
    }
    pass("Validity period", `until ${vc.validUntil.slice(0, 10)}`);

    return { ok: true, checks };
}

module.exports = { verifyVc };

// Run directly: node packages/core/verify_vc.js [credential.json]
if (require.main === module) {
    const file = process.argv[2] || "build/credential.json";
    const vc = JSON.parse(fs.readFileSync(file, "utf8"));
    verifyVc(vc).then((result) => {
        for (const c of result.checks) {
            console.log(`${c.ok ? "✔" : "✘"} ${c.name}${c.detail ? "  (" + c.detail + ")" : ""}`);
        }
        console.log(result.ok ? "\nCredential is VALID" : "\nCredential is INVALID");
        process.exit(result.ok ? 0 : 1);
    });
}
