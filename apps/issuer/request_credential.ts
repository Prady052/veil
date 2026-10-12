// Plays the role of the WALLET for now: asks the issuer for a credential.
// The real wallet will do this from the browser.
// Run: npm run credential:request
import fs from "node:fs";
import { holderCommitment, randomField, type Subject } from "../../packages/core/src";

const ISSUER_URL = "http://localhost:3000";
const SECRET_FILE = "build/holder_secret.txt";
const VC_FILE = "build/credential.json";

// The claims the holder asks the issuer to certify (mock data)
const claims: Subject = {
    name: "Sameer Patil",
    dateOfBirth: "1995-03-14",
    state: "MH",
    incomeBand: "5L-8L",
    employmentStatus: "employed",
};

async function main() {
    // 1. The wallet creates its secret ONCE and reuses it afterwards.
    //    It never leaves the device.
    let holderSecret: string;
    if (fs.existsSync(SECRET_FILE)) {
        holderSecret = fs.readFileSync(SECRET_FILE, "utf8").trim();
    } else {
        holderSecret = randomField().toString();
        fs.writeFileSync(SECRET_FILE, holderSecret);
        console.log("Created new holder secret:", SECRET_FILE);
    }

    // 2. Only the commitment (the one-way "fingerprint") is sent to the issuer
    const commitment = holderCommitment(holderSecret).toString();

    // 3. Ask the issuer for a credential
    const response = await fetch(`${ISSUER_URL}/issue`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ holderCommitment: commitment, ...claims }),
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

main().catch((err) => {
    console.error("Error:", err instanceof Error ? err.message : err);
    process.exit(1);
});
