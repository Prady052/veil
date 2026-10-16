import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
    plugins: [react()],
    // The prover runs in a Web Worker; build it as a modern module like the rest of the app
    worker: {
        format: "es",
    },
    server: {
        port: 5173,
        strictPort: true, // fail loudly if the port is taken, instead of silently moving
    },
});
