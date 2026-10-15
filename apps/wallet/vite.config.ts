import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
    plugins: [react()],
    server: {
        port: 5173,
        strictPort: true, // fail loudly if the port is taken, instead of silently moving
    },
});
