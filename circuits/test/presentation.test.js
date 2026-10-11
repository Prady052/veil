// Tests for circuits/presentation.circom.
// Most of these are NEGATIVE tests: inputs that must NOT produce a witness.
// Run: npm test
const path = require("path");
const assert = require("assert");
const crypto = require("crypto");
const { wasm: wasmTester } = require("circom_tester");
const { buildEddsa } = require("circomlibjs");
const { encodeAttributes, hashAttributes } = require("../../packages/core/encoding");
const { encodePredicates } = require("../../packages/core/predicates");

const ROOT = path.join(__dirname, "..", "..");

// A test credential. Individual tests override single fields.
const BASE_CLAIMS = {
    credentialId: "123456789",
    holderCommitment: "987654321",
    name: "Asha Rao",
    dateOfBirth: "1995-03-14",
    state: "MH",
    incomeBand: "5L-8L",
    employmentStatus: "employed",
    issuedAt: "2026-10-11",
    expiresAt: "2031-10-11",
};

const AGE_18 = { attr: "dateOfBirth", op: "<=", value: "2008-10-11" };

describe("Presentation circuit", function () {
    this.timeout(300000); // compiling the circuit takes a while

    let circuit;
    let eddsa;
    let F;
    let issuerKey;
    let issuerPub;

    before(async function () {
        circuit = await wasmTester(path.join(ROOT, "circuits", "presentation.circom"), {
            include: [path.join(ROOT, "node_modules")],
            output: path.join(ROOT, "build", "test"),
        });
        eddsa = await buildEddsa();
        F = eddsa.babyJub.F;
        issuerKey = crypto.randomBytes(32);
        issuerPub = eddsa.prv2pub(issuerKey);
    });

    // Issue a credential: encode, hash, sign.
    // `signingKey` lets a test play a fake issuer.
    async function issue(overrides = {}, signingKey = issuerKey) {
        const attrs = await encodeAttributes({ ...BASE_CLAIMS, ...overrides });
        const M = await hashAttributes(attrs);
        const sig = eddsa.signPoseidon(signingKey, F.e(M));
        return {
            attrs: attrs.map(String),
            R8x: F.toObject(sig.R8[0]).toString(),
            R8y: F.toObject(sig.R8[1]).toString(),
            S: sig.S.toString(),
        };
    }

    // Circuit input: the credential (private) plus what the VERIFIER supplies (public):
    // the trusted issuer key and the predicates.
    async function makeInput(credential, predicates = []) {
        return {
            ...credential,
            Ax: F.toObject(issuerPub[0]).toString(),
            Ay: F.toObject(issuerPub[1]).toString(),
            ...(await encodePredicates(predicates)),
        };
    }

    // A witness exists and satisfies every constraint
    async function expectPass(input) {
        const witness = await circuit.calculateWitness(input, true);
        await circuit.checkConstraints(witness);
    }

    // No witness exists: some rule is broken
    async function expectFail(input) {
        await assert.rejects(() => circuit.calculateWitness(input, true));
    }

    describe("valid presentations", function () {
        it("accepts a genuine credential with no predicates", async function () {
            await expectPass(await makeInput(await issue()));
        });

        it("accepts age >= 18", async function () {
            await expectPass(await makeInput(await issue(), [AGE_18]));
        });

        it("accepts three predicates at once", async function () {
            await expectPass(await makeInput(await issue(), [
                AGE_18,
                { attr: "incomeBand", op: "<=", value: "5L-8L" },
                { attr: "state", op: "==", value: "MH" },
            ]));
        });

        it("accepts four predicates (every slot used)", async function () {
            await expectPass(await makeInput(await issue(), [
                AGE_18,
                { attr: "incomeBand", op: ">=", value: "2.5L-5L" },
                { attr: "state", op: "==", value: "MH" },
                { attr: "employmentStatus", op: "==", value: "employed" },
            ]));
        });

        it("accepts == on a hashed attribute (disclosing the name)", async function () {
            await expectPass(await makeInput(await issue(), [
                { attr: "name", op: "==", value: "Asha Rao" },
            ]));
        });
    });

    describe("boundaries", function () {
        it("<= accepts the boundary value itself (18th birthday is today)", async function () {
            const credential = await issue({ dateOfBirth: "2008-10-11" });
            await expectPass(await makeInput(credential, [AGE_18]));
        });

        it("<= rejects one day past the boundary (18 tomorrow)", async function () {
            const credential = await issue({ dateOfBirth: "2008-10-12" });
            await expectFail(await makeInput(credential, [AGE_18]));
        });

        it(">= accepts the boundary value itself", async function () {
            await expectPass(await makeInput(await issue(), [
                { attr: "incomeBand", op: ">=", value: "5L-8L" },
            ]));
        });

        it(">= rejects one step above the boundary", async function () {
            await expectFail(await makeInput(await issue(), [
                { attr: "incomeBand", op: ">=", value: "8L-12L" },
            ]));
        });
    });

    describe("forged credentials", function () {
        it("rejects an attribute changed after signing", async function () {
            const credential = await issue();
            credential.attrs[6] = "1"; // claim the lowest income band
            await expectFail(await makeInput(credential));
        });

        it("rejects two slots swapped", async function () {
            const credential = await issue();
            [credential.attrs[5], credential.attrs[6]] = [credential.attrs[6], credential.attrs[5]];
            await expectFail(await makeInput(credential));
        });

        it("rejects a tampered signature", async function () {
            const credential = await issue();
            credential.S = (BigInt(credential.S) + 1n).toString();
            await expectFail(await makeInput(credential));
        });

        it("rejects a credential signed by someone who is not the issuer", async function () {
            // A minor signs their own fake date of birth with their own key
            const attackerKey = crypto.randomBytes(32);
            const credential = await issue({ dateOfBirth: "1990-01-01" }, attackerKey);
            // makeInput still supplies the REAL issuer's public key
            await expectFail(await makeInput(credential, [AGE_18]));
        });
    });

    describe("false predicates", function () {
        it("rejects a false <= (a minor claiming to be 18)", async function () {
            const credential = await issue({ dateOfBirth: "2012-06-01" });
            await expectFail(await makeInput(credential, [AGE_18]));
        });

        it("rejects a false == (wrong state)", async function () {
            await expectFail(await makeInput(await issue(), [
                { attr: "state", op: "==", value: "KA" },
            ]));
        });

        it("rejects a false == on a hashed attribute (wrong name)", async function () {
            await expectFail(await makeInput(await issue(), [
                { attr: "name", op: "==", value: "Someone Else" },
            ]));
        });

        it("rejects when one predicate of several is false", async function () {
            await expectFail(await makeInput(await issue(), [
                AGE_18,
                { attr: "state", op: "==", value: "MH" },
                { attr: "incomeBand", op: "<=", value: "<2.5L" }, // false
            ]));
        });
    });

    describe("malformed requests", function () {
        it("rejects a range comparison on a hashed attribute", async function () {
            await expectFail(await makeInput(await issue(), [
                { attr: "name", op: ">=", value: "Asha Rao" },
            ]));
        });

        it("rejects a comparison value that does not fit in 32 bits", async function () {
            const input = await makeInput(await issue(), [AGE_18]);
            input.predValue[0] = (2n ** 32n).toString();
            await expectFail(input);
        });

        it("rejects an unknown operator code", async function () {
            const input = await makeInput(await issue(), [AGE_18]);
            input.predOp[0] = "7";
            await expectFail(input);
        });

        it("rejects a slot number that does not exist", async function () {
            const input = await makeInput(await issue(), [AGE_18]);
            input.predAttr[0] = "10";
            await expectFail(input);
        });
    });
});
