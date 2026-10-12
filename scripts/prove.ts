// Plays the HOLDER: answer a verifier's request with a zero-knowledge proof.
// The real wallet will do this in the browser.
// Run: npm run prove -- <request.json> [credential.json] [presentation.json]
import fs from "node:fs";
import * as snarkjs from "snarkjs";
import {
    buildCircuitInput,
    resolveIssuerKey,
    type Presentation,
    type PresentationRequest,
    type VerifiableCredential,
} from "../packages/core/src";

const WASM_FILE = "build/presentation_js/presentation.wasm";
const ZKEY_FILE = "build/presentation_final.zkey";
const SECRET_FILE = "build/holder_secret.txt"; // the wallet's secret, created by request_credential.ts

async function main() {
    const [requestFile, vcFile = "build/credential.json", outFile = "build/presentation.json"] = process.argv.slice(2);
    if (!requestFile) {
        console.log("usage: npm run prove -- <request.json> [credential.json] [presentation.json]");
        process.exit(1);
    }

    for (const file of [WASM_FILE, ZKEY_FILE]) {
        if (!fs.existsSync(file)) throw new Error(`${file} is missing: run "npm run setup" first`);
    }
    if (!fs.existsSync(SECRET_FILE)) throw new Error(`${SECRET_FILE} is missing: this device has no holder secret`);
    const holderSecret = fs.readFileSync(SECRET_FILE, "utf8").trim();

    const request: PresentationRequest = JSON.parse(fs.readFileSync(requestFile, "utf8"));
    const vc: VerifiableCredential = JSON.parse(fs.readFileSync(vcFile, "utf8"));

    // The proof will be bound to this domain and nonce. A browser wallet must also check
    // that request.domain is the site it is really talking to (Week 5).
    console.log(`Request from ${request.domain}`);

    if (vc.issuer !== request.issuer) {
        throw new Error(`The verifier wants a credential from ${request.issuer}`);
    }

    const issuerKey = await resolveIssuerKey(vc.issuer, vc.proof.verificationMethod);
    const input = buildCircuitInput(vc, issuerKey, request, holderSecret);

    // Witness + proof in one call. If any rule is broken, no witness exists and this throws.
    const start = Date.now();
    let proof: Presentation["proof"];
    let publicSignals: string[];
    try {
        ({ proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_FILE, ZKEY_FILE));
    } catch {
        console.log("Cannot prove: this credential does not satisfy the request.");
        process.exit(1);
    }
    console.log(`Proof generated in ${((Date.now() - start) / 1000).toFixed(1)} s`);

    // What is sent to the verifier. No attributes and no signature. The verifier rebuilds
    // the public inputs itself; the pseudonym is included only if it asked for one.
    const presentation: Presentation = {
        verificationMethod: vc.proof.verificationMethod,
        proof,
    };
    if (request.pseudonym) {
        presentation.pseudonym = publicSignals[0]; // the circuit's output
        console.log(`Revealing your pseudonym for ${request.domain}`);
    }
    fs.writeFileSync(outFile, JSON.stringify(presentation, null, 2));
    console.log("Wrote", outFile);
    process.exit(0); // snarkjs keeps worker threads alive; exit explicitly
}

main().catch((err) => {
    console.error("Error:", err instanceof Error ? err.message : err);
    process.exit(1);
});
