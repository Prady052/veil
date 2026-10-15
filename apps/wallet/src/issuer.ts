// Talking to the issuer. The wallet sends the claims and its holder COMMITMENT,
// never the secret, and gets back a signed credential.
import type { Subject, VerifiableCredential } from "@veil/core";

// Set VITE_ISSUER_URL to use another issuer, e.g. a deployed one in Week 8
export const ISSUER_URL: string = import.meta.env.VITE_ISSUER_URL ?? "http://localhost:3000";

export async function requestCredential(subject: Subject, holderCommitment: string): Promise<VerifiableCredential> {
    let response: Response;
    try {
        response = await fetch(`${ISSUER_URL}/issue`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ holderCommitment, ...subject }),
        });
    } catch {
        throw new Error(`Could not reach the issuer at ${ISSUER_URL}. Is it running?`);
    }

    const body = await response.json();
    if (!response.ok) {
        // Fastify's schema errors use `message`; the issuer's own refusals use `error`
        throw new Error(`The issuer refused: ${body.message || body.error || `HTTP ${response.status}`}`);
    }
    return body as VerifiableCredential;
}
