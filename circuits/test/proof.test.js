// Proof-level tests: one real Groth16 proof, checked the way a verifier checks it.
// The verifier rebuilds the public inputs from ITS OWN request, so a proof made for
// one request must fail for any other.
//
// These need the proving and verification keys: run `npm run setup` first.
const path = require("path");
const fs = require("fs");
const assert = require("assert");
const crypto = require("crypto");
const snarkjs = require("snarkjs");
const { buildEddsa, buildPoseidon } = require("circomlibjs");
const { encodeAttributes, hashAttributes } = require("../../packages/core/encoding");
const { newRequest, buildCircuitInput, buildPublicSignals } = require("../../packages/core/presentation");

const ROOT = path.join(__dirname, "..", "..");
const WASM_FILE = path.join(ROOT, "build", "presentation_js", "presentation.wasm");
const ZKEY_FILE = path.join(ROOT, "build", "presentation_final.zkey");
const VKEY_FILE = path.join(ROOT, "build", "presentation_vkey.json");

const HOLDER_SECRET = "1234567890123456789";
const AGE_18 = { attr: "dateOfBirth", op: "<=", value: "2008-10-11" };

describe("Presentation proofs", function () {
    this.timeout(120000);

    let vkey;
    let issuerKey;      // the trusted issuer's public key, { x, y }
    let otherIssuerKey; // some other issuer
    let request;        // a request with no pseudonym, and the proof made for it
    let proof;
    let nymRequest;     // a request that asks for a pseudonym, and the proof made for it
    let nymProof;
    let nym;            // the pseudonym that proof reveals

    before(async function () {
        if (![WASM_FILE, ZKEY_FILE, VKEY_FILE].every((file) => fs.existsSync(file))) {
            console.log("    (skipped: run `npm run setup` to create the proving and verification keys)");
            this.skip();
        }
        vkey = JSON.parse(fs.readFileSync(VKEY_FILE, "utf8"));

        const eddsa = await buildEddsa();
        const poseidon = await buildPoseidon();
        const F = eddsa.babyJub.F;
        const publicKeyOf = (privateKey) => {
            const point = eddsa.prv2pub(privateKey);
            return { x: F.toObject(point[0]).toString(), y: F.toObject(point[1]).toString() };
        };

        const issuerPrivateKey = crypto.randomBytes(32);
        issuerKey = publicKeyOf(issuerPrivateKey);
        otherIssuerKey = publicKeyOf(crypto.randomBytes(32));

        // Issue one credential, bound to HOLDER_SECRET
        const attrs = await encodeAttributes({
            credentialId: "123456789",
            holderCommitment: poseidon.F.toObject(poseidon([BigInt(HOLDER_SECRET)])).toString(),
            name: "Asha Rao",
            dateOfBirth: "1995-03-14",
            state: "MH",
            incomeBand: "5L-8L",
            employmentStatus: "employed",
            issuedAt: "2026-10-11",
            expiresAt: "2031-10-11",
        });
        const sig = eddsa.signPoseidon(issuerPrivateKey, F.e(await hashAttributes(attrs)));
        const vc = {
            proof: {
                attributes: attrs.map(String),
                signature: {
                    R8x: F.toObject(sig.R8[0]).toString(),
                    R8y: F.toObject(sig.R8[1]).toString(),
                    S: sig.S.toString(),
                },
            },
        };

        // The holder's side: answer a request with a proof (and the circuit's output)
        async function prove(forRequest) {
            const input = await buildCircuitInput(vc, issuerKey, forRequest, HOLDER_SECRET);
            try {
                return await snarkjs.groth16.fullProve(input, WASM_FILE, ZKEY_FILE);
            } catch (err) {
                throw new Error("Could not prove with the keys in build/. If the circuit changed, run `npm run setup`.");
            }
        }

        // The age gate asks, the holder answers
        const wanted = { issuer: "did:web:issuer.example", predicates: [AGE_18] };
        request = newRequest(wanted, "agegate.example");
        ({ proof } = await prove(request));

        // The same again, this time asking for a pseudonym
        nymRequest = newRequest({ ...wanted, pseudonym: true }, "agegate.example");
        const result = await prove(nymRequest);
        nymProof = result.proof;
        nym = result.publicSignals[0];
    });

    // Check the plain proof against a request, as a verifier would
    async function verifies(checkedRequest, key = issuerKey) {
        return snarkjs.groth16.verify(vkey, await buildPublicSignals(key, checkedRequest), proof);
    }

    // Check a proof against the pseudonym request, with the pseudonym the holder claims
    async function verifiesWithPseudonym(claimedPseudonym, whichProof = nymProof) {
        const signals = await buildPublicSignals(issuerKey, nymRequest, claimedPseudonym);
        return snarkjs.groth16.verify(vkey, signals, whichProof);
    }

    it("verifies for the request it was made for", async function () {
        assert.strictEqual(await verifies(request), true);
    });

    it("rejects a replay: the same verifier's next request has a new nonce", async function () {
        const nextRequest = newRequest(request, request.domain);
        assert.notStrictEqual(nextRequest.nonce, request.nonce);
        assert.strictEqual(await verifies(nextRequest), false);
    });

    it("rejects a proof forwarded to another verifier's domain", async function () {
        assert.strictEqual(await verifies({ ...request, domain: "rental.example" }), false);
    });

    it("rejects a proof presented for different predicates", async function () {
        const stricter = [AGE_18, { attr: "state", op: "==", value: "MH" }];
        assert.strictEqual(await verifies({ ...request, predicates: stricter }), false);
    });

    it("rejects a proof checked against another issuer's key", async function () {
        assert.strictEqual(await verifies(request, otherIssuerKey), false);
    });

    it("verifies with the pseudonym the holder really has", async function () {
        assert.notStrictEqual(nym, "0");
        assert.strictEqual(await verifiesWithPseudonym(nym), true);
    });

    it("rejects a holder claiming a different pseudonym", async function () {
        const someoneElses = (BigInt(nym) + 1n).toString();
        assert.strictEqual(await verifiesWithPseudonym(someoneElses), false);
    });

    it("rejects a proof made without a pseudonym when one was asked for", async function () {
        assert.strictEqual(await verifiesWithPseudonym(nym, proof), false);
    });
});
