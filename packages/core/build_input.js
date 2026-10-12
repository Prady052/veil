// Turn a credential plus a verifier's request into the input file for the presentation circuit.
// Useful for running the witness generator by hand.
// Run: node packages/core/build_input.js <request.json> [credential.json] [output.json]
const fs = require("fs");
const { resolveIssuerKey, buildCircuitInput } = require("./presentation");

const SECRET_FILE = "build/holder_secret.txt"; // the wallet's secret, created by request_credential.js

async function main() {
    const requestFile = process.argv[2];
    const vcFile = process.argv[3] || "build/credential.json";
    const outFile = process.argv[4] || "build/presentation_input.json";
    if (!requestFile) {
        console.log("usage: node packages/core/build_input.js <request.json> [credential.json] [output.json]");
        process.exit(1);
    }

    const request = JSON.parse(fs.readFileSync(requestFile, "utf8"));
    const vc = JSON.parse(fs.readFileSync(vcFile, "utf8"));

    // The issuer's public key comes from its DID document, never from the credential itself
    const issuerKey = await resolveIssuerKey(vc.issuer, vc.proof.verificationMethod);
    const holderSecret = fs.readFileSync(SECRET_FILE, "utf8").trim();
    const input = await buildCircuitInput(vc, issuerKey, request.predicates, holderSecret);

    fs.writeFileSync(outFile, JSON.stringify(input, null, 2));
    console.log("Wrote", outFile);
}

main().catch((err) => {
    console.error("Error:", err.message);
    process.exit(1);
});
