// Check a Veil credential the way a wallet would right after receiving it:
// resolve the issuer's DID, fetch its public key, and verify the signature.
// Node-only for now: it uses circomlibjs for the EdDSA check.
import { buildEddsa } from "circomlibjs";
import { resolveIssuerKey, type PublicKey } from "./did";
import { encodeAttributes, hashAttributes } from "./encoding";
import { PROOF_TYPE, claimsFromVc, type VerifiableCredential } from "./vc";

export interface Check {
    name: string;
    ok: boolean;
    detail: string;
}

export interface VerifyResult {
    ok: boolean;
    checks: Check[];
}

const message = (err: unknown) => (err instanceof Error ? err.message : String(err));

// Runs the checks in order and stops at the first one that fails
export async function verifyVc(vc: VerifiableCredential, now = new Date()): Promise<VerifyResult> {
    const checks: Check[] = [];
    const pass = (name: string, detail = "") => {
        checks.push({ name, ok: true, detail });
    };
    const fail = (name: string, detail: string): VerifyResult => {
        checks.push({ name, ok: false, detail });
        return { ok: false, checks };
    };

    // 1. Is this the kind of credential we understand?
    if (!vc.proof || vc.proof.type !== PROOF_TYPE) {
        return fail("Proof type", `expected ${PROOF_TYPE}`);
    }
    pass("Proof type", PROOF_TYPE);

    // 2. Resolve the issuer's DID: fetch did.json from the issuer's website.
    // 3. Get the signing key the credential points to.
    if (!vc.proof.verificationMethod.startsWith(vc.issuer + "#")) {
        return fail("Issuer key", "key does not belong to the issuer");
    }
    let publicKey: PublicKey;
    try {
        publicKey = await resolveIssuerKey(vc.issuer, vc.proof.verificationMethod);
    } catch (err) {
        // Fetching the document failed, or the document doesn't contain a usable key
        const fetching = /^(Could not|DID document)/.test(message(err));
        if (!fetching) pass("Resolve DID", vc.issuer);
        return fail(fetching ? "Resolve DID" : "Issuer key", message(err));
    }
    pass("Resolve DID", vc.issuer);
    pass("Issuer key", vc.proof.verificationMethod);

    // 4. Do the readable claims match the 10 signed numbers?
    //    We re-encode the claims ourselves and compare.
    let attrs: bigint[];
    try {
        attrs = encodeAttributes(claimsFromVc(vc));
    } catch (err) {
        return fail("Claims match attributes", message(err));
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
    let signatureOk = false;
    try {
        const sig = vc.proof.signature;
        signatureOk = eddsa.verifyPoseidon(
            F.e(hashAttributes(attrs)),
            { R8: [F.e(sig.R8x), F.e(sig.R8y)], S: BigInt(sig.S) },
            [F.e(publicKey.x), F.e(publicKey.y)],
        );
    } catch (err) {
        return fail("Signature", message(err));
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
