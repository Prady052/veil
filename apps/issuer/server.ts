import Fastify from "fastify";
import { buildEddsa } from "circomlibjs";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
    PROOF_TYPE,
    buildDidDocument,
    buildUnsignedVc,
    claimsFromVc,
    didFromHost,
    encodeAttributes,
    hashAttributes,
    type PublicKey,
    type Subject,
    type VerifiableCredential,
} from "../../packages/core/src";

const PORT = 3000;
// The public address of this issuer. Its DID is derived from it.
const HOST = process.env.ISSUER_HOST || `localhost:${PORT}`;
const DID = didFromHost(HOST);
const DATA_DIR = path.join(__dirname, "data");
const KEY_FILE = path.join(DATA_DIR, "issuer_private.key");
const VALID_YEARS = 5;

// The body of POST /issue
type IssueBody = Subject & { holderCommitment: string };

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
function loadOrCreateKey(): Buffer {
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
    const publicKey: PublicKey = {
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
    app.post<{ Body: IssueBody }>("/issue", { schema: issueSchema }, async (request, reply) => {
        const { holderCommitment, ...subject } = request.body;

        const now = new Date();
        const until = new Date(now);
        until.setUTCFullYear(until.getUTCFullYear() + VALID_YEARS);

        const unsigned = buildUnsignedVc({
            did: DID,
            credentialId: BigInt("0x" + crypto.randomBytes(16).toString("hex")).toString(),
            holderCommitment,
            subject,
            validFrom: now.toISOString(),
            validUntil: until.toISOString(),
        });

        // Encode the claims into the 10 field elements. Bad input (unknown state,
        // impossible date, ...) throws here, before anything is signed.
        let attrs: bigint[];
        try {
            attrs = encodeAttributes(claimsFromVc(unsigned));
        } catch (err) {
            return reply.code(400).send({ error: err instanceof Error ? err.message : String(err) });
        }

        // M = Poseidon(attrs), then sign M with the issuer's key
        const sig = eddsa.signPoseidon(privKey, F.e(hashAttributes(attrs)));

        const vc: VerifiableCredential = {
            ...unsigned,
            proof: {
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
            },
        };
        return vc;
    });

    await app.listen({ port: PORT });
}

main();
