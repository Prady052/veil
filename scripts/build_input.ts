// Turn a credential plus a verifier's request into the input file for the presentation circuit.
// Useful for running the witness generator by hand.
// Run: npm run input -- <request.json> [credential.json] [output.json]
import fs from "node:fs";
import {
    buildCircuitInput,
    resolveIssuerKey,
    type PresentationRequest,
    type VerifiableCredential,
} from "../packages/core/src";

const SECRET_FILE = "build/holder_secret.txt"; // the wallet's secret, created by request_credential.ts

async function main() {
    const [requestFile, vcFile = "build/credential.json", outFile = "build/presentation_input.json"] = process.argv.slice(2);
    if (!requestFile) {
        console.log("usage: npm run input -- <request.json> [credential.json] [output.json]");
        process.exit(1);
    }

    const request: PresentationRequest = JSON.parse(fs.readFileSync(requestFile, "utf8"));
    const vc: VerifiableCredential = JSON.parse(fs.readFileSync(vcFile, "utf8"));

    // The issuer's public key comes from its DID document, never from the credential itself
    const issuerKey = await resolveIssuerKey(vc.issuer, vc.proof.verificationMethod);
    const holderSecret = fs.readFileSync(SECRET_FILE, "utf8").trim();
    const input = buildCircuitInput(vc, issuerKey, request, holderSecret);

    fs.writeFileSync(outFile, JSON.stringify(input, null, 2));
    console.log("Wrote", outFile);
}

main().catch((err) => {
    console.error("Error:", err instanceof Error ? err.message : err);
    process.exit(1);
});
