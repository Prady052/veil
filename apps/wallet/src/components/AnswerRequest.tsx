import { useState } from "react";
import {
    buildCircuitInput,
    parseRequest,
    resolveIssuerKey,
    satisfies,
    type Presentation,
    type PresentationRequest,
    type VerifiableCredential,
} from "@veil/core";
import { describePredicate, revealsValue } from "../describe";
import { proveInWorker } from "../proving/client";
import type { ProgressEvent } from "../proving/prover";

interface Props {
    credential: VerifiableCredential;
    secret: string;
}

function megabytes(bytes: number): string {
    return (bytes / 1024 / 1024).toFixed(1) + " MB";
}

// Answer a verifier's request: read it, show the holder what is being asked, and only after
// they agree, make the proof. The presentation is the only thing that leaves the wallet.
export function AnswerRequest({ credential, secret }: Props) {
    const [pasted, setPasted] = useState("");
    const [request, setRequest] = useState<PresentationRequest | null>(null);
    const [busy, setBusy] = useState(false);
    const [progress, setProgress] = useState<ProgressEvent | null>(null);
    const [presentation, setPresentation] = useState<string | null>(null);
    const [seconds, setSeconds] = useState(0);
    const [error, setError] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);

    function reset() {
        setRequest(null);
        setPresentation(null);
        setError(null);
        setCopied(false);
    }

    // 1. Read the request. It comes from outside, so it is checked field by field.
    function read() {
        reset();
        try {
            setRequest(parseRequest(JSON.parse(pasted)));
        } catch (err) {
            setError(err instanceof SyntaxError ? "That is not valid JSON." : err instanceof Error ? err.message : String(err));
        }
    }

    // 2. The holder agreed: prove in the worker and build the presentation
    async function share(req: PresentationRequest) {
        setBusy(true);
        setError(null);
        setProgress(null);
        try {
            const issuerKey = await resolveIssuerKey(credential.issuer, credential.proof.verificationMethod);
            const input = buildCircuitInput(credential, issuerKey, req, secret);
            const result = await proveInWorker(input, setProgress);
            const answer: Presentation = {
                verificationMethod: credential.proof.verificationMethod,
                proof: result.proof,
            };
            if (req.pseudonym) answer.pseudonym = result.publicSignals[0]; // the circuit's output
            setSeconds(result.provingMs / 1000);
            setPresentation(JSON.stringify(answer, null, 2));
        } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        } finally {
            setBusy(false);
        }
    }

    async function copy() {
        if (!presentation) return;
        await navigator.clipboard.writeText(presentation);
        setCopied(true);
    }

    function download() {
        if (!presentation) return;
        const link = document.createElement("a");
        link.href = URL.createObjectURL(new Blob([presentation], { type: "application/json" }));
        link.download = "presentation.json";
        link.click();
        URL.revokeObjectURL(link.href);
    }

    // What the wallet can work out before proving anything
    const sameIssuer = request ? request.issuer === credential.issuer : false;
    const results = request ? request.predicates.map((p) => satisfies(credential.proof.attributes, p)) : [];
    const canAnswer = sameIssuer && results.every(Boolean);

    return (
        <section>
            <h2>Answer a request</h2>
            <p className="muted">Paste a verifier's request (the JSON from <code>npm run request</code>).</p>
            <textarea
                rows={6}
                value={pasted}
                onChange={(e) => { setPasted(e.target.value); reset(); }}
                placeholder='{ "issuer": "did:web:…", "domain": "…", "nonce": "…", "predicates": [ … ] }'
                spellCheck={false}
            />
            <div className="actions">
                <button onClick={read} disabled={!pasted.trim() || busy}>Read request</button>
            </div>

            {request && (
                <div className="request">
                    <h3>{request.domain} asks you to prove:</h3>
                    <ul className="checks">
                        {request.predicates.length === 0 && <li>That you hold a credential from this issuer</li>}
                        {request.predicates.map((p, i) => (
                            <li key={i} className={results[i] ? "ok" : "bad"}>
                                {results[i] ? "✔" : "✘"} {describePredicate(p)}
                                {revealsValue(p) && <span className="warn"> (this reveals the value itself)</span>}
                            </li>
                        ))}
                    </ul>
                    {request.pseudonym && (
                        <p className="warn">
                            It also asks for your pseudonym, so it can recognise you when you come back. Other sites can't link it to you.
                        </p>
                    )}
                    {!sameIssuer && (
                        <p className="bad">It only accepts credentials from {request.issuer}; yours is from {credential.issuer}.</p>
                    )}
                    {sameIssuer && !canAnswer && <p className="bad">Your credential doesn't meet every condition, so no proof can be made.</p>}
                    <p className="muted">
                        It will learn only that these are true{request.pseudonym ? ", plus your pseudonym for this site" : ""}. Not your
                        name, your date of birth, or anything else in your credential. (Week 5 adds a check that this request really
                        comes from {request.domain}.)
                    </p>
                    {!presentation && (
                        <div className="actions">
                            <button onClick={() => share(request)} disabled={!canAnswer || busy}>
                                {busy ? "Proving…" : "Share proof"}
                            </button>
                            <button className="secondary" onClick={() => { setPasted(""); reset(); }} disabled={busy}>
                                Decline
                            </button>
                        </div>
                    )}
                </div>
            )}

            {busy && progress?.stage === "downloading" && (
                <div className="progress">
                    <p>Downloading the proving files: {megabytes(progress.loaded)} of {megabytes(progress.total)}</p>
                    <progress value={progress.loaded} max={progress.total || 1} />
                </div>
            )}
            {busy && progress?.stage === "proving" && <p>Proving…</p>}

            {error && <p className="bad">{error}</p>}

            {presentation && (
                <div className="request">
                    <h3>Your presentation (proof made in {seconds.toFixed(1)} s)</h3>
                    <p className="muted">This is everything the verifier receives.</p>
                    <pre className="json">{presentation}</pre>
                    <div className="actions">
                        <button onClick={copy}>{copied ? "Copied" : "Copy"}</button>
                        <button className="secondary" onClick={download}>Download presentation.json</button>
                    </div>
                </div>
            )}
        </section>
    );
}
