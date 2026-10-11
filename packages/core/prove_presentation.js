// Plays the HOLDER: answer a verifier's request with a zero-knowledge proof.
// The real wallet (Week 4) will do this in the browser.
// Run: node packages/core/prove_presentation.js <request.json> [credential.json] [presentation.json]
const snarkjs = require("snarkjs");
const fs = require("fs");
const { resolveIssuerKey, buildCircuitInput } = require("./presentation");

const WASM_FILE = "build/presentation_js/presentation.wasm";
const ZKEY_FILE = "build/presentation_final.zkey";

async function main() {
    const requestFile = process.argv[2];
    const vcFile = process.argv[3] || "build/credential.json";
    const outFile = process.argv[4] || "build/presentation.json";
    if (!requestFile) {
        console.log("usage: node packages/core/prove_presentation.js <request.json> [credential.json] [presentation.json]");
        process.exit(1);
    }

    for (const file of [WASM_FILE, ZKEY_FILE]) {
        if (!fs.existsSync(file)) throw new Error(`${file} is missing: compile the circuit and run the setup first`);
    }

    const request = JSON.parse(fs.readFileSync(requestFile, "utf8"));
    const vc = JSON.parse(fs.readFileSync(vcFile, "utf8"));

    if (vc.issuer !== request.issuer) {
        throw new Error(`The verifier wants a credential from ${request.issuer}`);
    }

    const issuerKey = await resolveIssuerKey(vc.issuer, vc.proof.verificationMethod);
    const input = await buildCircuitInput(vc, issuerKey, request.predicates);

    // Witness + proof in one call. If any rule is broken, no witness exists and this throws.
    const start = Date.now();
    let proof;
    try {
        ({ proof } = await snarkjs.groth16.fullProve(input, WASM_FILE, ZKEY_FILE));
    } catch (err) {
        console.log("Cannot prove: this credential does not satisfy the request.");
        process.exit(1);
    }
    console.log(`Proof generated in ${((Date.now() - start) / 1000).toFixed(1)} s`);

    // What is sent to the verifier. No attributes, no signature, no public inputs:
    // the verifier rebuilds the public inputs itself.
    const presentation = {
        verificationMethod: vc.proof.verificationMethod, // which issuer key signed the credential
        proof,
    };
    fs.writeFileSync(outFile, JSON.stringify(presentation, null, 2));
    console.log("Wrote", outFile);
    process.exit(0); // snarkjs keeps worker threads alive; exit explicitly
}

main().catch((err) => {
    console.error("Error:", err.message);
    process.exit(1);
});
