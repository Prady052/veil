// Plays the VERIFIER: create a fresh request with a new nonce.
// Run: node packages/core/make_request.js <template.json> <domain> [request.json]
//   e.g. node packages/core/make_request.js circuits/test/request_age18.json agegate.example
const fs = require("fs");
const { newRequest } = require("./presentation");

const templateFile = process.argv[2];
const domain = process.argv[3];
const outFile = process.argv[4] || "build/request.json";
if (!templateFile || !domain) {
    console.log("usage: node packages/core/make_request.js <template.json> <domain> [request.json]");
    process.exit(1);
}

const template = JSON.parse(fs.readFileSync(templateFile, "utf8"));
const request = newRequest(template, domain);

fs.writeFileSync(outFile, JSON.stringify(request, null, 2));
console.log("Wrote", outFile);
console.log(JSON.stringify(request, null, 2));
