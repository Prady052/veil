// Witness-level tests for circuits/presentation.circom: can an input satisfy the rules?
// Most of these are NEGATIVE tests: inputs that must NOT produce a witness.
// Replay protection is a property of verification, so it is tested in proof.test.js.
// Run: npm test
const path = require("path");
const assert = require("assert");
const crypto = require("crypto");
const { wasm: wasmTester } = require("circom_tester");
const { buildEddsa, buildPoseidon } = require("circomlibjs");
const { encodeAttributes, hashAttributes } = require("../../packages/core/encoding");
const { encodePredicates } = require("../../packages/core/predicates");

const ROOT = path.join(__dirname, "..", "..");

// The wallet secrets of two different people
const HOLDER_SECRET = "1234567890123456789";
const OTHER_SECRET = "9876543210987654321";

// A test credential. Individual tests override single fields.
// holderCommitment is added in issue(): it is Poseidon(HOLDER_SECRET).
const BASE_CLAIMS = {
    credentialId: "123456789",
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
    let commitmentOf; // secret -> Poseidon(secret), as a decimal string
    let pseudonymOf;  // (secret, domainHash) -> Poseidon(secret, domainHash)

    before(async function () {
        const poseidon = await buildPoseidon();
        commitmentOf = (secret) => poseidon.F.toObject(poseidon([BigInt(secret)])).toString();
        pseudonymOf = (secret, domainHash) =>
            poseidon.F.toObject(poseidon([BigInt(secret), BigInt(domainHash)])).toString();
        circuit = await wasmTester(path.join(ROOT, "circuits", "presentation.circom"), {
            include: [path.join(ROOT, "node_modules")],
            output: path.join(ROOT, "build", "test"),
        });
        eddsa = await buildEddsa();
        F = eddsa.babyJub.F;
        issuerKey = crypto.randomBytes(32);
        issuerPub = eddsa.prv2pub(issuerKey);
    });

    // Issue a credential: encode, hash, sign. By default it is bound to HOLDER_SECRET.
    // `signingKey` lets a test play a fake issuer.
    async function issue(overrides = {}, signingKey = issuerKey) {
        const attrs = await encodeAttributes({
            ...BASE_CLAIMS,
            holderCommitment: commitmentOf(HOLDER_SECRET),
            ...overrides,
        });
        const M = await hashAttributes(attrs);
        const sig = eddsa.signPoseidon(signingKey, F.e(M));
        return {
            attrs: attrs.map(String),
            R8x: F.toObject(sig.R8[0]).toString(),
            R8y: F.toObject(sig.R8[1]).toString(),
            S: sig.S.toString(),
        };
    }

    // Circuit input: the credential and the prover's secret (private), plus what the
    // VERIFIER supplies (public): the trusted issuer key, the request's nonce and domain,
    // and the predicates. Any nonce and domain give a witness, so fixed values are fine here.
    // `overrides` replaces single inputs, e.g. { wantPseudonym: "1" }.
    async function makeInput(credential, predicates = [], holderSecret = HOLDER_SECRET, overrides = {}) {
        return {
            ...credential,
            holderSecret,
            Ax: F.toObject(issuerPub[0]).toString(),
            Ay: F.toObject(issuerPub[1]).toString(),
            nonce: "424242",
            domainHash: "777",
            wantPseudonym: "0",
            ...(await encodePredicates(predicates)),
            ...overrides,
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

    // The circuit's public output. In a witness, wire 0 is the constant 1 and outputs come next.
    async function pseudonymFor(input) {
        const witness = await circuit.calculateWitness(input, true);
        await circuit.checkConstraints(witness);
        return witness[1].toString();
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

    describe("holder binding", function () {
        it("accepts a credential issued to another holder when that holder proves", async function () {
            const credential = await issue({ holderCommitment: commitmentOf(OTHER_SECRET) });
            await expectPass(await makeInput(credential, [AGE_18], OTHER_SECRET));
        });

        it("rejects a stolen credential used with the thief's own secret", async function () {
            const credential = await issue(); // bound to HOLDER_SECRET
            await expectFail(await makeInput(credential, [AGE_18], OTHER_SECRET));
        });

        it("rejects a stolen credential re-pointed at the thief's commitment", async function () {
            const credential = await issue();
            credential.attrs[2] = commitmentOf(OTHER_SECRET); // breaks the issuer's signature
            await expectFail(await makeInput(credential, [AGE_18], OTHER_SECRET));
        });
    });

    describe("scoped pseudonym", function () {
        const SITE_A = "777"; // two verifiers' domain hashes
        const SITE_B = "888";

        it("outputs Poseidon(holderSecret, domainHash) when asked", async function () {
            const input = await makeInput(await issue(), [], HOLDER_SECRET, { wantPseudonym: "1", domainHash: SITE_A });
            assert.strictEqual(await pseudonymFor(input), pseudonymOf(HOLDER_SECRET, SITE_A));
        });

        it("outputs 0 when not asked", async function () {
            const input = await makeInput(await issue(), [], HOLDER_SECRET, { wantPseudonym: "0" });
            assert.strictEqual(await pseudonymFor(input), "0");
        });

        it("is the same for one holder at one verifier, even with a different credential", async function () {
            const first = await issue({ credentialId: "111" });
            const second = await issue({ credentialId: "222", incomeBand: "12L+" });
            const ask = { wantPseudonym: "1", domainHash: SITE_A };
            assert.strictEqual(
                await pseudonymFor(await makeInput(first, [], HOLDER_SECRET, ask)),
                await pseudonymFor(await makeInput(second, [], HOLDER_SECRET, ask)),
            );
        });

        it("differs for one holder at two verifiers", async function () {
            const credential = await issue();
            const atA = await pseudonymFor(await makeInput(credential, [], HOLDER_SECRET, { wantPseudonym: "1", domainHash: SITE_A }));
            const atB = await pseudonymFor(await makeInput(credential, [], HOLDER_SECRET, { wantPseudonym: "1", domainHash: SITE_B }));
            assert.notStrictEqual(atA, atB);
        });

        it("differs for two holders at one verifier", async function () {
            const ask = { wantPseudonym: "1", domainHash: SITE_A };
            const mine = await pseudonymFor(await makeInput(await issue(), [], HOLDER_SECRET, ask));
            const theirCredential = await issue({ holderCommitment: commitmentOf(OTHER_SECRET) });
            const theirs = await pseudonymFor(await makeInput(theirCredential, [], OTHER_SECRET, ask));
            assert.notStrictEqual(mine, theirs);
        });

        it("rejects a wantPseudonym flag that is not 0 or 1", async function () {
            await expectFail(await makeInput(await issue(), [], HOLDER_SECRET, { wantPseudonym: "2" }));
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
