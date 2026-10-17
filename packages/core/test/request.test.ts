// The wallet's two checks on a verifier's request, before any proving:
//   parseRequest: is the request well formed?
//   satisfies:    can this credential answer it? (the circuit's rules, in plain code)
import assert from "node:assert";
import { encodeAttributes, holderCommitment, newRequest, parseRequest, satisfies } from "../src";

// A credential's 10 signed numbers: born 1995-03-14, MH, 5L-8L, employed
const ATTRS = encodeAttributes({
    credentialId: "123456789",
    holderCommitment: holderCommitment("1234567890123456789").toString(),
    name: "Asha Rao",
    dateOfBirth: "1995-03-14",
    state: "MH",
    incomeBand: "5L-8L",
    employmentStatus: "employed",
    issuedAt: "2026-10-17",
    expiresAt: "2031-10-17",
});

describe("Wallet checks on a request", function () {
    describe("satisfies", function () {
        it("agrees with the circuit on <= and >=, including the boundary", function () {
            assert.strictEqual(satisfies(ATTRS, { attr: "dateOfBirth", op: "<=", value: "1995-03-14" }), true);
            assert.strictEqual(satisfies(ATTRS, { attr: "dateOfBirth", op: "<=", value: "1995-03-13" }), false);
            assert.strictEqual(satisfies(ATTRS, { attr: "incomeBand", op: ">=", value: "5L-8L" }), true);
            assert.strictEqual(satisfies(ATTRS, { attr: "incomeBand", op: ">=", value: "8L-12L" }), false);
        });

        it("agrees with the circuit on == and in, including hashed attributes", function () {
            assert.strictEqual(satisfies(ATTRS, { attr: "state", op: "==", value: "MH" }), true);
            assert.strictEqual(satisfies(ATTRS, { attr: "state", op: "in", value: ["KA", "MH"] }), true);
            assert.strictEqual(satisfies(ATTRS, { attr: "state", op: "in", value: ["KA", "DL"] }), false);
            assert.strictEqual(satisfies(ATTRS, { attr: "name", op: "==", value: "Asha Rao" }), true);
        });

        it("refuses a range comparison on a hashed attribute, as the circuit does", function () {
            assert.strictEqual(satisfies(ATTRS, { attr: "name", op: ">=", value: "Asha Rao" }), false);
        });
    });

    describe("parseRequest", function () {
        const good = newRequest(
            { issuer: "did:web:localhost%3A3000", predicates: [{ attr: "state", op: "in", value: ["MH", "KA"] }] },
            "rental.example",
        );

        it("accepts a request made by newRequest, after a trip through JSON", function () {
            assert.deepStrictEqual(parseRequest(JSON.parse(JSON.stringify(good))), good);
        });

        it("refuses something that isn't an object", function () {
            assert.throws(() => parseRequest("hello"), /JSON object/);
            assert.throws(() => parseRequest([good]), /JSON object/);
        });

        it("refuses a missing domain or a bad nonce", function () {
            assert.throws(() => parseRequest({ ...good, domain: "" }), /domain/);
            assert.throws(() => parseRequest({ ...good, nonce: "12abc" }), /nonce/);
        });

        it("refuses an unknown attribute or operator", function () {
            assert.throws(() => parseRequest({ ...good, predicates: [{ attr: "salary", op: "<=", value: "1" }] }), /Unknown attribute/);
            assert.throws(() => parseRequest({ ...good, predicates: [{ attr: "state", op: "inn", value: "MH" }] }), /Unknown operator/);
        });

        it("refuses a predicate with no value", function () {
            assert.throws(() => parseRequest({ ...good, predicates: [{ attr: "name", op: "==" }] }), /attr, an op and a value/);
        });
    });
});
