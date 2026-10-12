// Plays the VERIFIER: check a holder's presentation against the verifier's own request.
// Run: node packages/core/verify_presentation.js <request.json> [presentation.json]
const snarkjs = require("snarkjs");
const fs = require("fs");
const { resolveIssuerKey, buildPublicSignals } = require("./presentation");

const VKEY_FILE = "build/presentation_vkey.json";
// Nonces this verifier has already accepted. A real verifier keeps these on its server.
const USED_NONCES_FILE = "build/used_nonces.json";

async function main() {
    const requestFile = process.argv[2];
    const presentationFile = process.argv[3] || "build/presentation.json";
    if (!requestFile) {
        console.log("usage: node packages/core/verify_presentation.js <request.json> [presentation.json]");
        process.exit(1);
    }

    const request = JSON.parse(fs.readFileSync(requestFile, "utf8"));
    const { verificationMethod, proof } = JSON.parse(fs.readFileSync(presentationFile, "utf8"));
    const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, "utf8"));

    // Each request may be answered once
    const usedNonces = fs.existsSync(USED_NONCES_FILE)
        ? JSON.parse(fs.readFileSync(USED_NONCES_FILE, "utf8"))
        : [];
    if (usedNonces.includes(request.nonce)) {
        console.log("✘ Rejected: this request was already answered (replay)");
        process.exit(1);
    }

    // The holder names the key, but it must be a key of the issuer WE trust
    if (typeof verificationMethod !== "string" || !verificationMethod.startsWith(request.issuer + "#")) {
        console.log("✘ Rejected: the key does not belong to the trusted issuer");
        process.exit(1);
    }
    const issuerKey = await resolveIssuerKey(request.issuer, verificationMethod);

    // Build the public inputs OURSELVES from our own request: our domain, our nonce,
    // our predicates. Nothing here comes from the holder except the proof.
    const publicSignals = await buildPublicSignals(issuerKey, request);

    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    if (!ok) {
        console.log("✘ Rejected: the proof does not match this request");
        process.exit(1);
    }

    usedNonces.push(request.nonce);
    fs.writeFileSync(USED_NONCES_FILE, JSON.stringify(usedNonces, null, 2));

    console.log(`✔ Verified for ${request.domain}: the holder has a credential from ${request.issuer} where`);
    for (const p of request.predicates) {
        console.log(`    ${p.attr} ${p.op} ${p.value}`);
    }
    process.exit(0); // snarkjs keeps worker threads alive; exit explicitly
}

main().catch((err) => {
    console.error("Error:", err.message);
    process.exit(1);
});
