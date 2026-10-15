import { useState } from "react";
import { encodeText, holderCommitment, poseidon, randomField } from "@veil/core";

// circomlib's published test value for Poseidon(1, 2). The same number appeared in the
// Week 1 playground (Node) and must appear here (browser), or the two would disagree.
const POSEIDON_1_2 = "7853200120776062878684798364095072458815029376092732009249414926327459813530";

// Show the start and end of a long number
function short(n: string): string {
    return n.length > 20 ? `${n.slice(0, 10)}…${n.slice(-6)}` : n;
}

export function App() {
    const poseidonResult = poseidon([1n, 2n]).toString();
    const poseidonMatches = poseidonResult === POSEIDON_1_2;

    // Not saved anywhere yet: storage comes in the next step
    const [secret, setSecret] = useState<string | null>(null);
    const [domain, setDomain] = useState("agegate.example");

    let domainHash = "";
    try {
        domainHash = encodeText(domain).toString();
    } catch (err) {
        domainHash = err instanceof Error ? err.message : String(err);
    }

    return (
        <main>
            <header>
                <h1>Veil Wallet</h1>
                <p className="muted">
                    Step 4.6: the wallet's skeleton. This page runs Veil's shared code in the browser.
                </p>
            </header>

            <section>
                <h2>1. Same hash as the issuer and the circuit</h2>
                <p>
                    Poseidon(1, 2) computed in this browser:
                    <code className="number" title={poseidonResult}>{short(poseidonResult)}</code>
                </p>
                <p className={poseidonMatches ? "ok" : "bad"}>
                    {poseidonMatches
                        ? "✔ Matches circomlib's value, so the wallet and the circuit agree"
                        : "✘ Does not match circomlib: credentials made here would not verify"}
                </p>
            </section>

            <section>
                <h2>2. Holder secret and commitment</h2>
                <p className="muted">
                    The secret stays on this device. Only the commitment, Poseidon(secret), goes to the issuer.
                </p>
                <button onClick={() => setSecret(randomField().toString())}>
                    {secret ? "Make a new secret" : "Make a secret"}
                </button>
                {secret && (
                    <dl>
                        <dt>Secret (never leaves the wallet)</dt>
                        <dd><code className="number" title={secret}>{short(secret)}</code></dd>
                        <dt>Commitment (sent to the issuer)</dt>
                        <dd>
                            <code className="number" title={holderCommitment(secret).toString()}>
                                {short(holderCommitment(secret).toString())}
                            </code>
                        </dd>
                    </dl>
                )}
                <p className="muted">Not saved yet: reload the page and it is gone. Storage is the next step.</p>
            </section>

            <section>
                <h2>3. A verifier's domain hash</h2>
                <label htmlFor="domain">Domain</label>
                <input id="domain" value={domain} onChange={(e) => setDomain(e.target.value)} spellCheck={false} />
                <p>
                    Domain hash:
                    <code className="number" title={domainHash}>{short(domainHash)}</code>
                </p>
                <p className="muted">
                    The same number a verifier puts in its public inputs. Change one letter and it changes completely.
                </p>
            </section>
        </main>
    );
}
