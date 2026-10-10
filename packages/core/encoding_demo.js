const { encodeAttributes, hashAttributes } = require("./encoding");

async function main() {
    const attrs = await encodeAttributes({
        credentialId: "12345",
        holderCommitment: "999",
        name: "Sameer Patil",
        dateOfBirth: "1995-03-14",
        state: "MH",
        incomeBand: "5L-8L",
        employmentStatus: "employed",
        issuedAt: "2026-10-10",
        expiresAt: "2031-10-10",
    });

    attrs.forEach((a, i) => console.log(`[${i}]`, a.toString()));
    console.log("M =", (await hashAttributes(attrs)).toString());
}

main();