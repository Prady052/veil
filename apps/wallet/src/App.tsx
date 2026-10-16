import { useEffect, useState } from "react";
import {
    holderCommitment,
    poseidon,
    verifyVc,
    type Check,
    type Subject,
    type VerifiableCredential,
    type VerifyResult,
} from "@veil/core";
import { Checks } from "./components/Checks";
import { CredentialForm } from "./components/CredentialForm";
import { CredentialView } from "./components/CredentialView";
import { TestProof } from "./components/TestProof";
import { ISSUER_URL, requestCredential } from "./issuer";
import { forgetWallet, loadCredential, loadOrCreateSecret, saveCredential } from "./storage";

// circomlib's published test value for Poseidon(1, 2): the wallet's hash must match the circuit's
const POSEIDON_1_2 = "7853200120776062878684798364095072458815029376092732009249414926327459813530";

function short(n: string): string {
    return n.length > 20 ? `${n.slice(0, 10)}…${n.slice(-6)}` : n;
}

// The wallet's own extra check: is this credential bound to OUR secret?
// The issuer could, by mistake or on purpose, sign a different commitment. Such a credential
// would pass every other check, yet this wallet could never use it.
function boundToThisWallet(vc: VerifiableCredential, secret: string): Check {
    const ok = vc.credentialSubject.holderCommitment === holderCommitment(secret).toString();
    return { name: "Bound to this wallet", ok, detail: ok ? "" : "the commitment is not this wallet's" };
}

// The six credential checks, plus the binding check
async function checkCredential(vc: VerifiableCredential, secret: string): Promise<VerifyResult> {
    const result = await verifyVc(vc);
    if (!result.ok) return result;
    const binding = boundToThisWallet(vc, secret);
    return { ok: binding.ok, checks: [...result.checks, binding] };
}

export function App() {
    const [secret, setSecret] = useState<string | null>(null);
    const [credential, setCredential] = useState<VerifiableCredential | null>(null);
    const [result, setResult] = useState<VerifyResult | null>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // On start: load (or create) the secret, then load and re-check any saved credential
    useEffect(() => {
        (async () => {
            const s = await loadOrCreateSecret();
            setSecret(s);
            const saved = await loadCredential();
            if (saved) {
                setCredential(saved);
                setResult(await checkCredential(saved, s));
            }
        })().catch((err) => setError(String(err)));
    }, []);

    // Ask the issuer, check what comes back, and keep it only if every check passes
    async function getCredential(subject: Subject) {
        if (!secret) return;
        setBusy(true);
        setError(null);
        setResult(null);
        try {
            const vc = await requestCredential(subject, holderCommitment(secret).toString());
            const checked = await checkCredential(vc, secret);
            setResult(checked);
            if (checked.ok) {
                await saveCredential(vc);
                setCredential(vc);
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        } finally {
            setBusy(false);
        }
    }

    async function recheck() {
        if (!credential || !secret) return;
        setResult(null);
        setResult(await checkCredential(credential, secret));
    }

    async function forget() {
        if (!confirm("Delete this wallet's secret and credential? The credential can never be used again.")) return;
        await forgetWallet();
        setCredential(null);
        setResult(null);
        setSecret(await loadOrCreateSecret()); // a brand-new wallet
    }

    const poseidonOk = poseidon([1n, 2n]).toString() === POSEIDON_1_2;

    return (
        <main>
            <header>
                <h1>Veil Wallet</h1>
                <p className="muted">Your credential stays on this device. Websites get proofs about it, never the credential.</p>
            </header>

            <section>
                <h2>This wallet</h2>
                {secret ? (
                    <dl>
                        <dt>Holder commitment (the only thing the issuer sees)</dt>
                        <dd><code className="number" title={holderCommitment(secret).toString()}>{short(holderCommitment(secret).toString())}</code></dd>
                        <dt>Holder secret</dt>
                        <dd className="muted">Saved on this device only. Never shown, never sent.</dd>
                    </dl>
                ) : (
                    <p className="muted">Opening the wallet…</p>
                )}
            </section>

            <section>
                <h2>Credential</h2>
                {credential ? (
                    <>
                        <CredentialView vc={credential} />
                        <div className="actions">
                            <button onClick={recheck}>Check again</button>
                            <button className="danger" onClick={forget}>Forget this wallet</button>
                        </div>
                    </>
                ) : (
                    <>
                        <p className="muted">No credential yet. Ask the issuer at <code>{ISSUER_URL}</code> for one.</p>
                        <CredentialForm busy={busy || !secret} onSubmit={getCredential} />
                    </>
                )}
                {error && <p className="bad">{error}</p>}
                {result && (
                    <>
                        <h3>{result.ok ? "Checks passed" : "Checks failed: the credential was not saved"}</h3>
                        <Checks checks={result.checks} />
                    </>
                )}
            </section>

            {credential && secret && result?.ok && <TestProof credential={credential} secret={secret} />}

            <footer className="muted">
                {poseidonOk ? "✔" : "✘"} Shared code check: Poseidon in this browser {poseidonOk ? "matches" : "does NOT match"} the circuit's
            </footer>
        </main>
    );
}
