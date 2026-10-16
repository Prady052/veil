// The Web Worker: a second thread that runs the proof, so the page stays responsive.
// It talks to the page only through messages.
//   page -> worker:  { input }
//   worker -> page:  { type: "progress", ... } then { type: "done", ... } or { type: "error", ... }
import type { CircuitInput } from "@veil/core";
import { prove } from "./prover";

self.onmessage = async (event: MessageEvent<{ input: CircuitInput }>) => {
    try {
        const result = await prove(event.data.input, (progress) => {
            self.postMessage({ type: "progress", progress });
        });
        self.postMessage({ type: "done", result });
    } catch (err) {
        self.postMessage({ type: "error", message: err instanceof Error ? err.message : String(err) });
    }
};
