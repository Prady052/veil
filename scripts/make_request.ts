// Plays the VERIFIER: create a fresh request with a new nonce.
// Run: npm run request -- <template.json> <domain> [request.json]
//   e.g. npm run request -- circuits/test/request_age18.json agegate.example
import fs from "node:fs";
import { newRequest, type RequestTemplate } from "../packages/core/src";

const [templateFile, domain, outFile = "build/request.json"] = process.argv.slice(2);
if (!templateFile || !domain) {
    console.log("usage: npm run request -- <template.json> <domain> [request.json]");
    process.exit(1);
}

const template: RequestTemplate = JSON.parse(fs.readFileSync(templateFile, "utf8"));
const request = newRequest(template, domain);

fs.writeFileSync(outFile, JSON.stringify(request, null, 2));
console.log("Wrote", outFile);
console.log(JSON.stringify(request, null, 2));
