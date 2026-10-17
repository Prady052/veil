import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
    <StrictMode>
        <App />
    </StrictMode>,
);

// The service worker (public/sw.js) keeps the app and the proving files on the device.
// Only in a production build: in development it would serve old files and fight Vite's reloading.
if (import.meta.env.PROD && "serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch((err) => console.error("Service worker:", err));
}
