// Compile the presentation circuit and run the Groth16 circuit-specific setup (Phase 2).
// Run this after every change to a .circom file: npm run setup
//
// Produces in build/:
//   presentation.r1cs, presentation_js/presentation.wasm   (compiled circuit)
//   presentation_final.zkey                                (proving key)
//   presentation_vkey.json                                 (verification key)
// and copies the three files the wallet needs into apps/wallet/public/circuit/, with version.json:
// a fingerprint of the proving files, so the wallet never uses a cached copy of old ones.
import { execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import * as snarkjs from "snarkjs";

const CIRCUIT = "circuits/presentation.circom";
const BUILD = "build";
const PTAU = `${BUILD}/pot14_final.ptau`; // Phase 1, made once (see docs/design.md, Trusted setup)
const R1CS = `${BUILD}/presentation.r1cs`;
const ZKEY_0 = `${BUILD}/presentation_0000.zkey`;
const ZKEY_FINAL = `${BUILD}/presentation_final.zkey`;
const VKEY = `${BUILD}/presentation_vkey.json`;
const WASM = `${BUILD}/presentation_js/presentation.wasm`;
// The wallet serves these to the browser (Vite serves everything in public/ as-is)
const WALLET_DIR = "apps/wallet/public/circuit";

async function main() {
    if (!fs.existsSync(PTAU)) {
        throw new Error(`${PTAU} is missing. Create the Phase 1 file first (snarkjs powersoftau ...).`);
    }

    console.log("1/5 Compiling the circuit");
    execSync(`circom ${CIRCUIT} --r1cs --wasm --sym -o ${BUILD} -l node_modules`, { stdio: "inherit" });

    console.log("2/5 Phase 2 setup");
    await snarkjs.zKey.newZKey(R1CS, PTAU, ZKEY_0);

    // A single-party contribution with fresh randomness: fine for a demo, not for production
    console.log("3/5 Contributing randomness");
    const entropy = crypto.randomBytes(32).toString("hex");
    await snarkjs.zKey.contribute(ZKEY_0, ZKEY_FINAL, "veil dev setup", entropy);
    fs.unlinkSync(ZKEY_0);

    console.log("4/5 Exporting the verification key");
    const vkey = await snarkjs.zKey.exportVerificationKey(ZKEY_FINAL);
    fs.writeFileSync(VKEY, JSON.stringify(vkey, null, 2));

    // Copy, so the wallet always proves with the keys that match the current circuit
    console.log(`5/5 Copying the proving files to ${WALLET_DIR}`);
    fs.mkdirSync(WALLET_DIR, { recursive: true });
    for (const file of [WASM, ZKEY_FINAL, VKEY]) {
        fs.copyFileSync(file, `${WALLET_DIR}/${file.split("/").pop()}`);
    }
    // The fingerprint: it changes whenever the proving files do
    const hash = crypto.createHash("sha256");
    for (const file of [WASM, ZKEY_FINAL]) hash.update(fs.readFileSync(file));
    const version = hash.digest("hex").slice(0, 16);
    fs.writeFileSync(`${WALLET_DIR}/version.json`, JSON.stringify({ version }) + "\n");

    console.log(`Done: ${ZKEY_FINAL}, ${VKEY}`);
    process.exit(0); // snarkjs keeps worker threads alive; exit explicitly
}

main().catch((err) => {
    console.error("Error:", err instanceof Error ? err.message : err);
    process.exit(1);
});
