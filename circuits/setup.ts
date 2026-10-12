// Compile the presentation circuit and run the Groth16 circuit-specific setup (Phase 2).
// Run this after every change to a .circom file: npm run setup
//
// Produces in build/:
//   presentation.r1cs, presentation_js/presentation.wasm   (compiled circuit)
//   presentation_final.zkey                                (proving key)
//   presentation_vkey.json                                 (verification key)
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

async function main() {
    if (!fs.existsSync(PTAU)) {
        throw new Error(`${PTAU} is missing. Create the Phase 1 file first (snarkjs powersoftau ...).`);
    }

    console.log("1/4 Compiling the circuit");
    execSync(`circom ${CIRCUIT} --r1cs --wasm --sym -o ${BUILD} -l node_modules`, { stdio: "inherit" });

    console.log("2/4 Phase 2 setup");
    await snarkjs.zKey.newZKey(R1CS, PTAU, ZKEY_0);

    // A single-party contribution with fresh randomness: fine for a demo, not for production
    console.log("3/4 Contributing randomness");
    const entropy = crypto.randomBytes(32).toString("hex");
    await snarkjs.zKey.contribute(ZKEY_0, ZKEY_FINAL, "veil dev setup", entropy);
    fs.unlinkSync(ZKEY_0);

    console.log("4/4 Exporting the verification key");
    const vkey = await snarkjs.zKey.exportVerificationKey(ZKEY_FINAL);
    fs.writeFileSync(VKEY, JSON.stringify(vkey, null, 2));

    console.log(`Done: ${ZKEY_FINAL}, ${VKEY}`);
    process.exit(0); // snarkjs keeps worker threads alive; exit explicitly
}

main().catch((err) => {
    console.error("Error:", err instanceof Error ? err.message : err);
    process.exit(1);
});
