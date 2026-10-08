const { buildPoseidon, buildEddsa } = require("circomlibjs");
const crypto = require("crypto");
const fs = require("fs");

const KEY_FILE = "build/issuer_private.key";

async function main() {
    const dob = process.argv[2];   // e.g. 19950314
    const out = process.argv[3];   // e.g. circuits/test/age_check_ok.json
    if (!dob || !out) {
        console.log("usage: node packages/core/issue_age.js <dob YYYYMMDD> <output.json>");
        process.exit(1);
    }

    const poseidon = await buildPoseidon();
    const eddsa = await buildEddsa();
    const F = eddsa.babyJub.F;

    // Load the issuer key, or create it the first time.
    // The SAME key must sign every credential, just like a real issuer.
    let privKey;
    if (fs.existsSync(KEY_FILE)) {
        privKey = Buffer.from(fs.readFileSync(KEY_FILE, "utf8").trim(), "hex");
    } else {
        privKey = crypto.randomBytes(32);
        fs.writeFileSync(KEY_FILE, privKey.toString("hex"));
        console.log("Created new issuer key:", KEY_FILE);
    }
    const pubKey = eddsa.prv2pub(privKey);

    // Publish the public key (stand-in for the did:web document in Week 2)
    fs.writeFileSync("build/issuer_public.json", JSON.stringify({
        Ax: F.toObject(pubKey[0]).toString(),
        Ay: F.toObject(pubKey[1]).toString(),
    }, null, 2));

    // Issuer signs Poseidon(dob)
    const msg = poseidon([BigInt(dob)]);
    const sig = eddsa.signPoseidon(privKey, msg);

    // Today's date as YYYYMMDD (in the real system the verifier supplies this)
    const today = new Date().toISOString().slice(0, 10).replace(/-/g, "");

    const input = {
        dob: dob,
        R8x: F.toObject(sig.R8[0]).toString(),
        R8y: F.toObject(sig.R8[1]).toString(),
        S: sig.S.toString(),
        today: today,
        Ax: F.toObject(pubKey[0]).toString(),
        Ay: F.toObject(pubKey[1]).toString(),
    };

    fs.writeFileSync(out, JSON.stringify(input, null, 2));
    console.log("Wrote", out);
}

main();