// Check a credential file the way a wallet would right after receiving it.
// Run: npm run credential:verify -- [credential.json]
import fs from "node:fs";
import type { VerifiableCredential } from "../packages/core/src";
import { verifyVc } from "../packages/core/src/verifyVc";

async function main() {
    const file = process.argv[2] || "build/credential.json";
    const vc: VerifiableCredential = JSON.parse(fs.readFileSync(file, "utf8"));

    const result = await verifyVc(vc);
    for (const check of result.checks) {
        console.log(`${check.ok ? "✔" : "✘"} ${check.name}${check.detail ? "  (" + check.detail + ")" : ""}`);
    }
    console.log(result.ok ? "\nCredential is VALID" : "\nCredential is INVALID");
    process.exit(result.ok ? 0 : 1);
}

main().catch((err) => {
    console.error("Error:", err instanceof Error ? err.message : err);
    process.exit(1);
});
