// Turn a credential plus a verifier's request into the input file for the presentation circuit.
// The real wallet (Week 4) will do this in the browser.
// Run: node packages/core/build_input.js <request.json> [credential.json] [output.json]
const fs = require("fs");
const { didToUrl, publicKeyFromDidDocument } = require("./did");
const { encodePredicates } = require("./predicates");

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
    const response = await fetch(didToUrl(vc.issuer));
    if (!response.ok) throw new Error(`Could not resolve ${vc.issuer}: HTTP ${response.status}`);
    const issuerKey = publicKeyFromDidDocument(await response.json(), vc.proof.verificationMethod);

    const input = {
        // private
        attrs: vc.proof.attributes,
        R8x: vc.proof.signature.R8x,
        R8y: vc.proof.signature.R8y,
        S: vc.proof.signature.S,
        // public
        Ax: issuerKey.x,
        Ay: issuerKey.y,
        ...(await encodePredicates(request.predicates)),
    };

    fs.writeFileSync(outFile, JSON.stringify(input, null, 2));
    console.log("Wrote", outFile);
}

main().catch((err) => {
    console.error("Error:", err.message);
    process.exit(1);
});
