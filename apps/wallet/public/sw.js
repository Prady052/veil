// The wallet's service worker. It sits between the page and the network, and keeps on the
// device:
//   - the proving files (about 10 MB), so they download once per circuit version;
//   - the app itself, so the wallet opens without a network;
//   - the issuer's DID document, so the credential checks still run offline.
// Registered only in a production build (see src/main.tsx).

const APP = "veil-app";         // the page, its scripts and styles, the DID document
const CIRCUIT = "veil-circuit"; // the proving files

// Install: store the page and the scripts it loads, so the very next visit works offline
self.addEventListener("install", (event) => {
    event.waitUntil(
        (async () => {
            const cache = await caches.open(APP);
            const html = await (await fetch("/", { cache: "no-store" })).text();
            const assets = [...html.matchAll(/\/assets\/[^"']+/g)].map((m) => m[0]);
            await cache.addAll(["/", ...assets]);
        })(),
    );
    self.skipWaiting(); // take over without waiting for old tabs to close
});

self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (event) => {
    const request = event.request;
    if (request.method !== "GET") return; // e.g. POST /issue: straight to the network
    const url = new URL(request.url);
    const ours = url.origin === self.location.origin;

    if (ours && url.pathname.startsWith("/circuit/") && url.searchParams.has("v")) {
        event.respondWith(provingFile(event, url));
    } else if (ours && url.pathname.startsWith("/assets/")) {
        event.respondWith(cacheFirst(event, request));
    } else if (request.mode === "navigate" || ours || url.pathname === "/.well-known/did.json") {
        event.respondWith(networkFirst(request));
    }
    // Anything else: the browser fetches it as usual
});

// Proving files. The "?v=" in the URL is a fingerprint of the files (written by
// `npm run setup`), so a cached copy can never be out of date: new files get a new URL.
async function provingFile(event, url) {
    const cache = await caches.open(CIRCUIT);
    const cached = await cache.match(event.request);
    if (cached) return cached;

    const response = await fetch(event.request);
    if (response.ok) {
        // Store a copy in the background, so the page still sees the download progress.
        // Old versions of the same file are deleted first.
        const copy = response.clone();
        event.waitUntil(
            (async () => {
                for (const old of await cache.keys()) {
                    if (new URL(old.url).pathname === url.pathname) await cache.delete(old);
                }
                await cache.put(event.request, copy);
            })(),
        );
    }
    return response;
}

// Scripts and styles. Vite puts a fingerprint in their names, so a stored copy never goes stale.
async function cacheFirst(event, request) {
    const cache = await caches.open(APP);
    const cached = await cache.match(request);
    if (cached) return cached;
    const response = await fetch(request);
    if (response.ok) event.waitUntil(cache.put(request, response.clone()));
    return response;
}

// Everything that can change: try the network, keep the answer, and fall back to it offline
async function networkFirst(request) {
    const cache = await caches.open(APP);
    try {
        const response = await fetch(request);
        if (response.ok) await cache.put(request, response.clone());
        return response;
    } catch (err) {
        const cached = await cache.match(request, { ignoreSearch: true });
        if (cached) return cached;
        throw err;
    }
}
