// Making a Groth16 proof in the browser. Used inside the Web Worker (prover.worker.ts),
// and also directly on the page for the "without the worker" comparison.
import * as snarkjs from "snarkjs";
import type { CircuitInput, Groth16Proof } from "@veil/core";

// Copied into public/circuit/ by `npm run setup`, with version.json: a fingerprint of the files
const CIRCUIT_DIR = "/circuit";
const WASM_FILE = "presentation.wasm";       // computes the witness
const ZKEY_FILE = "presentation_final.zkey"; // the proving key

export type ProgressEvent =
    | { stage: "downloading"; loaded: number; total: number }
    | { stage: "proving" };

export interface ProveResult {
    proof: Groth16Proof;
    publicSignals: string[];
    provingMs: number; // witness + proof, not counting the download
}

interface ProvingFiles {
    wasm: Uint8Array;
    zkey: Uint8Array;
}

// Start a download and check the server answered
async function open(url: string): Promise<Response> {
    const response = await fetch(url);
    if (!response.ok || !response.body) {
        throw new Error(`Could not load ${url} (HTTP ${response.status}). Run "npm run setup" first.`);
    }
    return response;
}

// Read a download to the end, reporting bytes as they arrive
async function readAll(response: Response, onBytes: (n: number) => void): Promise<Uint8Array> {
    const reader = response.body!.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        size += value.length;
        onBytes(value.length);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
    }
    return bytes;
}

// The fingerprint changes whenever `npm run setup` makes new files. Putting it in the URL means
// a cached copy (in the service worker) can never be an old proving key for a new circuit.
async function circuitVersion(): Promise<string> {
    const response = await open(`${CIRCUIT_DIR}/version.json`);
    const { version } = (await response.json()) as { version: string };
    return version;
}

// The two proving files are about 10 MB. They are kept in memory while the wallet is open,
// and the service worker keeps them on the device between visits.
let files: Promise<ProvingFiles> | null = null;

function loadProvingFiles(onProgress: (e: ProgressEvent) => void): Promise<ProvingFiles> {
    files ??= (async () => {
        const v = await circuitVersion();
        const responses = await Promise.all([
            open(`${CIRCUIT_DIR}/${WASM_FILE}?v=${v}`),
            open(`${CIRCUIT_DIR}/${ZKEY_FILE}?v=${v}`),
        ]);
        // Both answers have arrived (not yet their contents), so the total size is known
        const total = responses.reduce((sum, r) => sum + Number(r.headers.get("content-length") || 0), 0);
        let loaded = 0;
        const onBytes = (n: number) => {
            loaded += n;
            onProgress({ stage: "downloading", loaded, total });
        };
        const [wasm, zkey] = await Promise.all(responses.map((r) => readAll(r, onBytes)));
        return { wasm, zkey };
    })().catch((err) => {
        files = null; // allow a retry after a failed download
        throw err;
    });
    return files;
}

export async function prove(input: CircuitInput, onProgress: (e: ProgressEvent) => void): Promise<ProveResult> {
    const { wasm, zkey } = await loadProvingFiles(onProgress);
    onProgress({ stage: "proving" });
    const start = performance.now();
    // Witness + proof in one call. If any rule is broken, no witness exists and this throws.
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
    return { proof, publicSignals, provingMs: performance.now() - start };
}
