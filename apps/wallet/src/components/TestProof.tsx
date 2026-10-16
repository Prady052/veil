import { useEffect, useRef, useState } from "react";
import {
    buildCircuitInput,
    buildPublicSignals,
    newRequest,
    resolveIssuerKey,
    type VerifiableCredential,
} from "@veil/core";
import { proveInWorker, proveOnPage } from "../proving/client";
import type { ProgressEvent, ProveResult } from "../proving/prover";

const VKEY_URL = "/circuit/presentation_vkey.json";

// The date 18 years ago, for "age >= 18". (On 29 Feb the browser rolls this over to 1 Mar,
// which is off by a day; fine for a self-test. Real verifiers will compute it properly.)
function eighteenYearsAgo(): string {
    const d = new Date();
    d.setUTCFullYear(d.getUTCFullYear() - 18);
    return d.toISOString().slice(0, 10);
}

function megabytes(bytes: number): string {
    return (bytes / 1024 / 1024).toFixed(1) + " MB";
}

interface Props {
    credential: VerifiableCredential;
    secret: string;
}

// A self-test: make a real proof of "age >= 18" in this browser, then check it the way a
// verifier would. Step 4.9 replaces this with answering a real verifier's request.
export function TestProof({ credential, secret }: Props) {
    const [useWorker, setUseWorker] = useState(true);
    const [busy, setBusy] = useState(false);
    const [progress, setProgress] = useState<ProgressEvent | null>(null);
    const [result, setResult] = useState<(ProveResult & { verified: boolean }) | null>(null);
    const [error, setError] = useState<string | null>(null);

    // A clock that ticks while proving. If the page's thread is blocked, it stops ticking.
    const [clock, setClock] = useState(0);
    const started = useRef(0);
    useEffect(() => {
        if (!busy) return;
        started.current = performance.now();
        const timer = setInterval(() => setClock(performance.now() - started.current), 100);
        return () => clearInterval(timer);
    }, [busy]);

    async function run() {
        setBusy(true);
        setError(null);
        setResult(null);
        setProgress(null);
        setClock(0);
        try {
            // 1. Play the verifier: a fresh request for "age >= 18"
            const request = newRequest(
                { issuer: credential.issuer, predicates: [{ attr: "dateOfBirth", op: "<=", value: eighteenYearsAgo() }] },
                "selftest.wallet",
            );
            // 2. The circuit input: the credential and secret are private, the rest public
            const issuerKey = await resolveIssuerKey(credential.issuer, credential.proof.verificationMethod);
            const input = buildCircuitInput(credential, issuerKey, request, secret);

            // 3. Prove, in the worker or on the page
            const proved = await (useWorker ? proveInWorker : proveOnPage)(input, setProgress);

            // 4. Check it exactly as a verifier would: public inputs rebuilt from the request
            const snarkjs = await import("snarkjs");
            const vkey = await (await fetch(VKEY_URL)).json();
            const verified: boolean = await snarkjs.groth16.verify(vkey, buildPublicSignals(issuerKey, request), proved.proof);
            setResult({ ...proved, verified });
        } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        } finally {
            setBusy(false);
        }
    }

    return (
        <section>
            <h2>Test proof</h2>
            <p className="muted">
                Makes a real zero-knowledge proof of "age ≥ 18" in this browser and checks it. The first run downloads
                the proving files (about 10 MB); later runs reuse them.
            </p>
            <label className="checkbox">
                <input type="checkbox" checked={!useWorker} onChange={(e) => setUseWorker(!e.target.checked)} disabled={busy} />
                Prove on the page's own thread, without the worker (for comparison)
            </label>
            <div className="actions">
                <button onClick={run} disabled={busy}>{busy ? "Working…" : "Make a test proof"}</button>
            </div>

            {busy && (
                <div className="progress">
                    {progress?.stage === "downloading" && (
                        <>
                            <p>Downloading the proving files: {megabytes(progress.loaded)} of {megabytes(progress.total)}</p>
                            <progress value={progress.loaded} max={progress.total || 1} />
                        </>
                    )}
                    {progress?.stage === "proving" && <p>Proving…</p>}
                    <p className="muted">Page clock: {(clock / 1000).toFixed(1)} s (it stops if the page is blocked)</p>
                </div>
            )}

            {error && <p className="bad">{error}</p>}
            {result && (
                <ul className="checks">
                    <li className="ok">✔ Proof made in {(result.provingMs / 1000).toFixed(1)} s ({useWorker ? "in the worker" : "on the page"})</li>
                    <li className={result.verified ? "ok" : "bad"}>
                        {result.verified ? "✔ Verified, exactly as a verifier would" : "✘ The proof did not verify"}
                    </li>
                    <li className="muted">Proof size: {JSON.stringify(result.proof).length} bytes as JSON</li>
                </ul>
            )}
        </section>
    );
}
