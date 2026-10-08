const snarkjs = require("snarkjs");
const fs = require("fs");

async function main() {
    const vkey = JSON.parse(fs.readFileSync("build/age_check_vkey.json"));
    const proof = JSON.parse(fs.readFileSync("build/age_check_proof.json"));

    // Trusted issuer key (Week 2: fetched from the issuer's did:web document)
    const issuer = JSON.parse(fs.readFileSync("build/issuer_public.json"));

    // The verifier chooses today's date itself
    const today = new Date().toISOString().slice(0, 10).replace(/-/g, "");

    // Build the public inputs OURSELVES, in the same order as the circuit:
    // today, Ax, Ay. We never trust the prover's public.json.
    const publicSignals = [today, issuer.Ax, issuer.Ay];

    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    console.log(ok ? "✔ Verified: holder is 18+" : "✘ Rejected");

    process.exit(0); // snarkjs keeps worker threads alive; exit explicitly
}

main();
