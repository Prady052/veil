// Plays the VERIFIER: check a holder's presentation against the verifier's own request.
// Run: npm run verify -- <request.json> [presentation.json]
import fs from "node:fs";
import * as snarkjs from "snarkjs";
import {
    buildPublicSignals,
    resolveIssuerKey,
    type Presentation,
    type PresentationRequest,
} from "../packages/core/src";

const VKEY_FILE = "build/presentation_vkey.json";
// Nonces this verifier has already accepted. A real verifier keeps these on its server.
const USED_NONCES_FILE = "build/used_nonces.json";
// Pseudonyms each site has seen before: { domain: [pseudonym, ...] }
const SEEN_PSEUDONYMS_FILE = "build/seen_pseudonyms.json";

function readJson<T>(file: string, fallback: T): T {
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : fallback;
}

function reject(reason: string): never {
    console.log(`✘ Rejected: ${reason}`);
    process.exit(1);
}

async function main() {
    const [requestFile, presentationFile = "build/presentation.json"] = process.argv.slice(2);
    if (!requestFile) {
        console.log("usage: npm run verify -- <request.json> [presentation.json]");
        process.exit(1);
    }

    const request: PresentationRequest = JSON.parse(fs.readFileSync(requestFile, "utf8"));
    const presentation: Presentation = JSON.parse(fs.readFileSync(presentationFile, "utf8"));
    const { verificationMethod, proof, pseudonym } = presentation;
    const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, "utf8"));

    // Each request may be answered once
    const usedNonces = readJson<string[]>(USED_NONCES_FILE, []);
    if (usedNonces.includes(request.nonce)) reject("this request was already answered (replay)");

    // The holder names the key, but it must be a key of the issuer WE trust
    if (typeof verificationMethod !== "string" || !verificationMethod.startsWith(request.issuer + "#")) {
        reject("the key does not belong to the trusted issuer");
    }
    const issuerKey = await resolveIssuerKey(request.issuer, verificationMethod);

    if (request.pseudonym && !/^[1-9]\d*$/.test(String(pseudonym))) {
        reject("we asked for a pseudonym and none was sent");
    }

    // Build the public inputs OURSELVES from our own request: our domain, our nonce,
    // our predicates. Nothing here comes from the holder except the proof.
    const publicSignals = buildPublicSignals(issuerKey, request, pseudonym);

    const ok: boolean = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    if (!ok) reject("the proof does not match this request");

    usedNonces.push(request.nonce);
    fs.writeFileSync(USED_NONCES_FILE, JSON.stringify(usedNonces, null, 2));

    console.log(`✔ Verified for ${request.domain}: the holder has a credential from ${request.issuer} where`);
    for (const p of request.predicates) {
        const value = Array.isArray(p.value) ? `[${p.value.join(", ")}]` : p.value;
        console.log(`    ${p.attr} ${p.op} ${value}`);
    }

    // A pseudonym lets THIS site recognise a returning user, and tells it nothing else
    if (request.pseudonym && pseudonym) {
        const seen = readJson<Record<string, string[]>>(SEEN_PSEUDONYMS_FILE, {});
        const known = seen[request.domain] || [];
        const returning = known.includes(pseudonym);
        console.log(`  Pseudonym: ${pseudonym.slice(0, 12)}...  (${returning ? "a returning user" : "first visit"})`);
        if (!returning) {
            seen[request.domain] = [...known, pseudonym];
            fs.writeFileSync(SEEN_PSEUDONYMS_FILE, JSON.stringify(seen, null, 2));
        }
    }
    process.exit(0); // snarkjs keeps worker threads alive; exit explicitly
}

main().catch((err) => {
    console.error("Error:", err instanceof Error ? err.message : err);
    process.exit(1);
});
