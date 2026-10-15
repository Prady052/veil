// The issuer signs with circomlibjs; the wallet checks with @zk-kit/eddsa-poseidon.
// These tests make sure the two libraries agree, in both directions:
// what the issuer signs is accepted, and anything altered is refused.
import assert from "node:assert";
import crypto from "node:crypto";
import { buildEddsa } from "circomlibjs";
import { hashAttributes, encodeAttributes, holderCommitment, verifyIssuerSignature, type PublicKey } from "../src";
import type { EddsaSignature } from "../src";

describe("Issuer signature check (browser-safe)", function () {
    let eddsa: any; // circomlibjs has no TypeScript types
    let F: any;
    let issuerKey: Buffer;
    let issuerPublicKey: PublicKey;
    let message: bigint;
    let signature: EddsaSignature;

    before(async function () {
        eddsa = await buildEddsa();
        F = eddsa.babyJub.F;
        issuerKey = crypto.randomBytes(32);
        const point = eddsa.prv2pub(issuerKey);
        issuerPublicKey = { x: F.toObject(point[0]).toString(), y: F.toObject(point[1]).toString() };

        // Sign a real credential hash, exactly as apps/issuer/server.ts does
        message = hashAttributes(encodeAttributes({
            credentialId: "123456789",
            holderCommitment: holderCommitment("1234567890123456789").toString(),
            name: "Asha Rao",
            dateOfBirth: "1995-03-14",
            state: "MH",
            incomeBand: "5L-8L",
            employmentStatus: "employed",
            issuedAt: "2026-10-16",
            expiresAt: "2031-10-16",
        }));
        signature = signWith(issuerKey, message);
    });

    function signWith(privateKey: Buffer, m: bigint): EddsaSignature {
        const sig = eddsa.signPoseidon(privateKey, F.e(m));
        return {
            R8x: F.toObject(sig.R8[0]).toString(),
            R8y: F.toObject(sig.R8[1]).toString(),
            S: sig.S.toString(),
        };
    }

    it("accepts a signature made by the issuer's library", function () {
        assert.strictEqual(verifyIssuerSignature(message, signature, issuerPublicKey), true);
    });

    it("accepts several different signatures, not just one lucky case", function () {
        for (let i = 0; i < 5; i++) {
            const key = crypto.randomBytes(32);
            const point = eddsa.prv2pub(key);
            const publicKey = { x: F.toObject(point[0]).toString(), y: F.toObject(point[1]).toString() };
            const m = BigInt(i) * 1000003n + 7n;
            assert.strictEqual(verifyIssuerSignature(m, signWith(key, m), publicKey), true);
        }
    });

    it("refuses a signature over a different message", function () {
        assert.strictEqual(verifyIssuerSignature(message + 1n, signature, issuerPublicKey), false);
    });

    it("refuses a tampered signature", function () {
        const tampered = { ...signature, S: (BigInt(signature.S) + 1n).toString() };
        assert.strictEqual(verifyIssuerSignature(message, tampered, issuerPublicKey), false);
    });

    it("refuses a signature checked against another key", function () {
        const point = eddsa.prv2pub(crypto.randomBytes(32));
        const otherKey = { x: F.toObject(point[0]).toString(), y: F.toObject(point[1]).toString() };
        assert.strictEqual(verifyIssuerSignature(message, signature, otherKey), false);
    });

    it("refuses garbage without throwing", function () {
        const garbage = { R8x: "not a number", R8y: "1", S: "1" };
        assert.strictEqual(verifyIssuerSignature(message, garbage, issuerPublicKey), false);
    });
});
