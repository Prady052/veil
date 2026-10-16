// Making a Groth16 proof in the browser. Used inside the Web Worker (prover.worker.ts),
// and also directly on the page for the "without the worker" comparison.
import * as snarkjs from "snarkjs";
import type { CircuitInput, Groth16Proof } from "@veil/core";

// Copied into public/circuit/ by `npm run setup`
const WASM_URL = "/circuit/presentation.wasm";       // computes the witness
const ZKEY_URL = "/circuit/presentation_final.zkey"; // the proving key

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

// Download a file, reporting bytes as they arrive
async function download(url: string, onBytes: (n: number) => void): Promise<Uint8Array> {
    const response = await fetch(url);
    if (!response.ok || !response.body) {
        throw new Error(`Could not load ${url} (HTTP ${response.status}). Run "npm run setup" first.`);
    }
    const reader = response.body.getReader();
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

// Ask the server for a file's size without downloading it
async function sizeOf(url: string): Promise<number> {
    const response = await fetch(url, { method: "HEAD" });
    return Number(response.headers.get("content-length") || 0);
}

// The two proving files are about 10 MB, so they are downloaded once and kept in memory
let files: Promise<ProvingFiles> | null = null;

function loadProvingFiles(onProgress: (e: ProgressEvent) => void): Promise<ProvingFiles> {
    files ??= (async () => {
        const total = (await sizeOf(WASM_URL)) + (await sizeOf(ZKEY_URL));
        let loaded = 0;
        const onBytes = (n: number) => {
            loaded += n;
            onProgress({ stage: "downloading", loaded, total });
        };
        const [wasm, zkey] = await Promise.all([download(WASM_URL, onBytes), download(ZKEY_URL, onBytes)]);
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
