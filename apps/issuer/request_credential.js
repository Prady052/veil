// Plays the role of the WALLET for now: asks the issuer for a credential.
// The real wallet (Week 4) will do this from the browser.
const { buildPoseidon } = require("circomlibjs");
const crypto = require("crypto");
const fs = require("fs");

const ISSUER_URL = "http://localhost:3000";
const SECRET_FILE = "build/holder_secret.txt";
const VC_FILE = "build/credential.json";

// The claims the holder asks the issuer to certify (mock data)
const claims = {
    name: "Sameer Patil",
    dateOfBirth: "1995-03-14",
    state: "MH",
    incomeBand: "5L-8L",
    employmentStatus: "employed",
};

async function main() {
    const poseidon = await buildPoseidon();

    // 1. The wallet creates its secret ONCE and reuses it afterwards.
    //    It never leaves the device.
    let holderSecret;
    if (fs.existsSync(SECRET_FILE)) {
        holderSecret = BigInt(fs.readFileSync(SECRET_FILE, "utf8").trim());
    } else {
        holderSecret = BigInt("0x" + crypto.randomBytes(31).toString("hex"));
        fs.writeFileSync(SECRET_FILE, holderSecret.toString());
        console.log("Created new holder secret:", SECRET_FILE);
    }

    // 2. Only the commitment (the one-way "fingerprint") is sent to the issuer
    const holderCommitment = poseidon.F.toObject(poseidon([holderSecret])).toString();

    // 3. Ask the issuer for a credential
    const response = await fetch(`${ISSUER_URL}/issue`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ holderCommitment, ...claims }),
    });
    const body = await response.json();

    if (!response.ok) {
        console.log(`Issuer refused (HTTP ${response.status}):`, body);
        return;
    }

    fs.writeFileSync(VC_FILE, JSON.stringify(body, null, 2));
    console.log("Credential saved to", VC_FILE);
    console.log(JSON.stringify(body, null, 2));
}

main();
