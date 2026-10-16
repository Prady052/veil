// The page's side of proving: send the input to the worker and wait for the result.
import type { CircuitInput } from "@veil/core";
import type { ProgressEvent, ProveResult } from "./prover";

type WorkerMessage =
    | { type: "progress"; progress: ProgressEvent }
    | { type: "done"; result: ProveResult }
    | { type: "error"; message: string };

// One worker for the whole session: it keeps the downloaded proving files between proofs
let worker: Worker | null = null;

function getWorker(): Worker {
    worker ??= new Worker(new URL("./prover.worker.ts", import.meta.url), { type: "module" });
    return worker;
}

export function proveInWorker(input: CircuitInput, onProgress: (e: ProgressEvent) => void): Promise<ProveResult> {
    return new Promise((resolve, reject) => {
        const w = getWorker();
        w.onmessage = (event: MessageEvent<WorkerMessage>) => {
            const message = event.data;
            if (message.type === "progress") onProgress(message.progress);
            else if (message.type === "done") resolve(message.result);
            else reject(new Error(message.message));
        };
        w.onerror = (event) => reject(new Error(event.message || "The proving worker crashed"));
        w.postMessage({ input });
    });
}

// The comparison: the same work on the page's own thread. The page freezes while it runs.
export async function proveOnPage(input: CircuitInput, onProgress: (e: ProgressEvent) => void): Promise<ProveResult> {
    const { prove } = await import("./prover");
    return prove(input, onProgress);
}
