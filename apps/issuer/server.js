const Fastify = require("fastify");
const { buildEddsa } = require("circomlibjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { didFromHost, buildDidDocument } = require("../../packages/core/did");

const PORT = 3000;
// The public address of this issuer. Its DID is derived from it.
const HOST = process.env.ISSUER_HOST || `localhost:${PORT}`;
const DID = didFromHost(HOST);
const DATA_DIR = path.join(__dirname, "data");
const KEY_FILE = path.join(DATA_DIR, "issuer_private.key");

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

    await app.listen({ port: PORT });
}

main();
