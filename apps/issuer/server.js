const Fastify = require("fastify");
const { buildEddsa } = require("circomlibjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { didFromHost, buildDidDocument } = require("../../packages/core/did");
const { encodeAttributes, hashAttributes } = require("../../packages/core/encoding");
const { PROOF_TYPE, buildUnsignedVc, claimsFromVc } = require("../../packages/core/vc");

const PORT = 3000;
// The public address of this issuer. Its DID is derived from it.
const HOST = process.env.ISSUER_HOST || `localhost:${PORT}`;
const DID = didFromHost(HOST);
const DATA_DIR = path.join(__dirname, "data");
const KEY_FILE = path.join(DATA_DIR, "issuer_private.key");
const VALID_YEARS = 5;

// What a credential request must look like. Fastify rejects anything else with a 400.
const issueSchema = {
    body: {
        type: "object",
        required: ["holderCommitment", "name", "dateOfBirth", "state", "incomeBand", "employmentStatus"],
        additionalProperties: false,
        properties: {
            holderCommitment: { type: "string" },
            name: { type: "string", minLength: 1, maxLength: 200 },
            dateOfBirth: { type: "string" },
            state: { type: "string" },
            incomeBand: { type: "string" },
            employmentStatus: { type: "string" },
        },
    },
};

// Load the issuer's private key, or create it on first start
function loadOrCreateKey() {
    if (fs.existsSync(KEY_FILE)) {
        return Buffer.from(fs.readFileSync(KEY_FILE, "utf8").trim(), "hex");
    }
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const key = crypto.randomBytes(32);
    fs.writeFileSync(KEY_FILE, key.toString("hex"));
    console.log("Created new issuer key:", KEY_FILE);
    return key;
}

async function main() {
    const eddsa = await buildEddsa();
    const F = eddsa.babyJub.F;

    const privKey = loadOrCreateKey();
    const pubKey = eddsa.prv2pub(privKey);
    const publicKey = {
        x: F.toObject(pubKey[0]).toString(),
        y: F.toObject(pubKey[1]).toString(),
    };

    const app = Fastify({ logger: true });

    // Health check: is the issuer running, and what is its public key?
    app.get("/", async () => {
        return { service: "veil-issuer", status: "ok", did: DID, publicKey };
    });

    // did:web resolution: anyone can fetch the issuer's public key from here
    const didDocument = buildDidDocument(DID, publicKey);
    app.get("/.well-known/did.json", async () => didDocument);

    // Issue a credential. The issuer signs mock data: there is no real identity check.
    app.post("/issue", { schema: issueSchema }, async (request, reply) => {
        const { holderCommitment, ...subject } = request.body;

        const now = new Date();
        const until = new Date(now);
        until.setUTCFullYear(until.getUTCFullYear() + VALID_YEARS);

        const vc = buildUnsignedVc({
            did: DID,
            credentialId: BigInt("0x" + crypto.randomBytes(16).toString("hex")).toString(),
            holderCommitment,
            subject,
            validFrom: now.toISOString(),
            validUntil: until.toISOString(),
        });

        // Encode the claims into the 10 field elements. Bad input (unknown state,
        // impossible date, ...) throws here, before anything is signed.
        let attrs;
        try {
            attrs = await encodeAttributes(claimsFromVc(vc));
        } catch (err) {
            return reply.code(400).send({ error: err.message });
        }

        // M = Poseidon(attrs), then sign M with the issuer's key
        const M = await hashAttributes(attrs);
        const sig = eddsa.signPoseidon(privKey, F.e(M));

        vc.proof = {
            type: PROOF_TYPE,
            created: now.toISOString(),
            verificationMethod: `${DID}#key-1`,
            proofPurpose: "assertionMethod",
            attributes: attrs.map(String),
            signature: {
                R8x: F.toObject(sig.R8[0]).toString(),
                R8y: F.toObject(sig.R8[1]).toString(),
                S: sig.S.toString(),
            },
        };
        return vc;
    });

    await app.listen({ port: PORT });
}

main();
